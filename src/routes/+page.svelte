<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount, onDestroy } from "svelte";
  import { fade, fly } from "svelte/transition";
  import { DataHandler } from "@vincjo/datatables";

  let interfaces: string[] = [];
  let selectedInterface: string = "";
  let sourceIp: string = "";
  let subnet: string = "";
  let scanResults: any[] = [];
  let loading: boolean = false;
  let theme: "light" | "dark" = "light";

  let handler: DataHandler<any>;
  let rows: any;

  let unsubscribeArpScan: () => void;
  let unsubscribePortScan: () => void;
  let unsubscribeDebug: () => void;

  let selectedIPs: { [key: string]: boolean } = {};

  onMount(async () => {
    interfaces = await invoke("get_network_interfaces");
    handler = new DataHandler([], { rowsPerPage: 10 });
    rows = handler.getRows();

    unsubscribeArpScan = await listen('arp-scan-result', (event) => {
      console.log('Received arp-scan-result event:', event);
      const result = event.payload;
      scanResults = [...scanResults, { ...result, expanded: false }];
      if (handler) {
        handler.setRows(scanResults);
      }
    });

    unsubscribePortScan = await listen('port-scan-result', (event) => {
      console.log('Received port-scan-result event:', event);
      const { ip_address, open_ports } = event.payload;
      scanResults = scanResults.map(result => 
        result.ip_address === ip_address 
          ? { ...result, open_ports, scanning: false }
          : result
      );
      if (handler) {
        handler.setRows(scanResults);
      }
    });

    unsubscribeDebug = await listen('debug', (event) => {
      console.log('Debug event:', event);
    });
  });

  onDestroy(() => {
    if (unsubscribeArpScan) unsubscribeArpScan();
    if (unsubscribePortScan) unsubscribePortScan();
    if (unsubscribeDebug) unsubscribeDebug();
  });

  async function startArpScan() {
    loading = true;
    try {
      const result = await invoke("arp_scan", {
        interfaceName: selectedInterface,
        sourceIp,
        subnet,
      });
      console.log("Raw ARP scan result:", result);
      if (result !== "[]" && result !== "null" && result !== null) {
        const newResults = JSON.parse(result).map((item: any) => ({
          ...item,
          expanded: false,
        }));
        scanResults = [...scanResults, ...newResults];
        if (handler) {
          handler.setRows(scanResults);
        }
        rows = handler.getRows();
      }
    } catch (error) {
      console.error("ARP scan error:", error);
      alert(`ARP scan failed: ${error}`);
    } finally {
      loading = false;
    }
  }

  function clearResults() {
    scanResults = [];
    selectedIPs = {};
    if (handler) {
      handler.setRows([]);
    }
    rows = handler.getRows();
  }

  async function scanPorts(ipAddress: string) {
    const index = scanResults.findIndex(
      (result) => result.ip_address === ipAddress
    );
    if (index !== -1) {
      scanResults[index].scanning = true;
      if (handler) {
        handler.setRows([...scanResults]);
      }
    }
    try {
      const openPorts = await invoke("scan_ports_for_ip", {
        ipAddress,
        scanCommon: true,
      });
      scanResults = scanResults.map((result) =>
        result.ip_address === ipAddress
          ? { ...result, open_ports: openPorts, scanning: false }
          : result
      );
      if (handler) {
        handler.setRows(scanResults);
      }
    } catch (error) {
      console.error("Port scan error:", error);
    } finally {
      if (index !== -1) {
        scanResults[index].scanning = false;
        if (handler) {
          handler.setRows([...scanResults]);
        }
      }
    }
  }

  async function scanAllPorts() {
    loading = true;
    try {
      for (const result of scanResults) {
        if (!result.open_ports) {
          await scanPorts(result.ip_address);
        }
      }
    } catch (error) {
      console.error("Error scanning all ports:", error);
      alert("An error occurred while scanning all ports. Please try again.");
    } finally {
      loading = false;
    }
  }

  function toggleExpand(ipAddress: string) {
    scanResults = scanResults.map((result) =>
      result.ip_address === ipAddress
        ? { ...result, expanded: !result.expanded }
        : result
    );
    if (handler) {
      handler.setRows(scanResults);
    }
  }

  async function saveReport() {
    try {
      await invoke("save_report", { reportData: scanResults });
      alert("Report saved successfully!");
    } catch (error) {
      console.error("Failed to save report:", error);
      alert("Error saving report. Please try again.");
    }
  }

  function toggleTheme() {
    theme = theme === "light" ? "business" : "light";
    document.documentElement.setAttribute("data-theme", theme);
  }

  function toggleSelectAll() {
    const allSelected = Object.keys(selectedIPs).length === scanResults.length;
    selectedIPs = allSelected
      ? {}
      : Object.fromEntries(scanResults.map(result => [result.ip_address, true]));
  }

  function toggleSelectIP(ipAddress: string) {
    selectedIPs[ipAddress] = !selectedIPs[ipAddress];
    if (!selectedIPs[ipAddress]) {
      delete selectedIPs[ipAddress];
    }
    selectedIPs = {...selectedIPs};
  }

  async function copySelectedIPs() {
    const selectedIPList = Object.keys(selectedIPs);
    const pythonList = `[${selectedIPList.map(ip => `'${ip}'`).join(', ')}]`;
    
    try {
      await navigator.clipboard.writeText(pythonList);
      alert('Selected IPs copied to clipboard as a Python list!');
    } catch (err) {
      console.error('Failed to copy text: ', err);
      alert('Failed to copy to clipboard. Please try again.');
    }
  }
</script>

<div class="container mx-auto p-4 min-h-screen bg-base-200" data-theme={theme}>
  <div class="navbar bg-base-100 rounded-box shadow-xl mb-8">
    <div class="flex-1">
      <span class="text-xl font-bold">Rusty ARP Scanner</span>
    </div>
    <div class="flex-none">
      <button class="btn btn-square btn-ghost" on:click={toggleTheme}>
        {#if theme === "light"}
          <svg
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            class="w-6 h-6"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
            />
          </svg>
        {:else}
          <svg
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            class="w-6 h-6"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
            />
          </svg>
        {/if}
      </button>
    </div>
  </div>

  <div
    class="card bg-base-100 shadow-xl mb-8"
    in:fly={{ y: 50, duration: 500 }}
    out:fade
  >
    <div class="card-body">
      <h2 class="card-title text-2xl mb-4">Network Scanner</h2>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="form-control">
          <label class="label" for="interfaceName">
            <span class="label-text">Interface Name</span>
          </label>
          <select
            id="interfaceName"
            class="select select-bordered w-full"
            bind:value={selectedInterface}
          >
            <option value="">Select an interface</option>
            {#each interfaces as iface}
              <option value={iface}>{iface}</option>
            {/each}
          </select>
        </div>
        <div class="form-control">
          <label class="label" for="sourceIp">
            <span class="label-text">Source IP</span>
          </label>
          <input
            id="sourceIp"
            type="text"
            class="input input-bordered w-full"
            bind:value={sourceIp}
            placeholder="Enter source IP"
          />
        </div>
        <div class="form-control">
          <label class="label" for="subnet">
            <span class="label-text">Subnet</span>
          </label>
          <input
            id="subnet"
            type="text"
            class="input input-bordered w-full"
            bind:value={subnet}
            placeholder="Enter subnet"
          />
        </div>
      </div>
      <div class="card-actions justify-end mt-4">
        <button
          class="btn btn-primary"
          on:click={startArpScan}
          disabled={loading}
        >
          {#if loading}
            <span class="loading loading-spinner"></span>
          {/if}
          Start ARP Scan
        </button>
        <button
          class="btn btn-secondary"
          on:click={clearResults}
          disabled={loading || scanResults.length === 0}
        >
          Clear Results
        </button>
      </div>
    </div>
  </div>

  {#if scanResults.length > 0}
    <div class="card bg-base-100 shadow-xl" in:fade>
      <div class="card-body">
        <div class="flex justify-between items-center mb-4">
          <h2 class="card-title text-2xl">Scan Results</h2>
          <div class="space-x-2">
            <button class="btn btn-accent" on:click={saveReport}>Save Report</button>
            <button class="btn btn-primary" on:click={scanAllPorts} disabled={loading}>
              {#if loading}
                <span class="loading loading-spinner"></span>
              {/if}
              Scan All Ports
            </button>
            <button class="btn btn-secondary" on:click={copySelectedIPs} disabled={Object.keys(selectedIPs).length === 0}>
              Copy Selected IPs
            </button>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="table w-full">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    class="checkbox"
                    on:change={toggleSelectAll}
                    checked={Object.keys(selectedIPs).length === scanResults.length}
                  />
                </th>
                <th>IP Address</th>
                <th>MAC Address</th>
                <th>Open Ports</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each $rows as result}
                <tr class="hover">
                  <td>
                    <input
                      type="checkbox"
                      class="checkbox"
                      checked={!!selectedIPs[result.ip_address]}
                      on:change={() => toggleSelectIP(result.ip_address)}
                    />
                  </td>
                  <td>{result.ip_address}</td>
                  <td>{result.mac_address}</td>
                  <td>
                    {#if result.open_ports}
                      <button
                        class="btn btn-xs"
                        on:click={() => toggleExpand(result.ip_address)}
                      >
                        {result.expanded ? "Hide" : "Show"} ({result.open_ports.length})
                      </button>
                    {:else}
                      Not scanned
                    {/if}
                  </td>
                  <td>
                    <button
                      class="btn btn-sm btn-outline"
                      on:click={() => scanPorts(result.ip_address)}
                      disabled={result.scanning}
                    >
                      {#if result.scanning}
                        <span class="loading loading-spinner loading-xs"></span>
                      {/if}
                      Scan Ports
                    </button>
                  </td>
                </tr>
                {#if result.expanded}
                  <tr transition:fade>
                    <td colspan="5">
                      <div class="p-4 bg-base-200 rounded-box">
                        <h4 class="font-bold mb-2">Open Ports:</h4>
                        <ul class="list-disc list-inside">
                          {#each result.open_ports as port}
                            <li>{port}</li>
                          {/each}
                        </ul>
                      </div>
                    </td>
                  </tr>
                {/if}
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  :global(html) {
    background-color: theme("colors.base-200");
  }
</style>