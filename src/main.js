const { invoke, event } = window.__TAURI__;

// Function to populate the interface dropdown
function populateInterfaceDropdown() {
  invoke('get_network_interfaces')
    .then(interfaceNames => {
      const interfaceSelect = document.getElementById('interfaceName');
      // Clear the dropdown before populating
      interfaceSelect.innerHTML = '';
      interfaceNames.forEach(name => {
        const option = document.createElement('option');
        option.value = name;
        option.textContent = name;
        interfaceSelect.appendChild(option);
      });
    })
    .catch(error => {
      console.error('Error fetching network interfaces:', error);
      displayError(error);
    });
}

// Function to display error messages
function displayError(error) {
  const resultsElement = document.getElementById('scanResults');
  const errorDiv = document.createElement('div');
  errorDiv.textContent = `Error: ${error}`;
  errorDiv.style.color = 'red';
  resultsElement.appendChild(errorDiv);
}

// Function to clear the DataTable results
function clearResults() {
  const resultsTable = $('#scanResults').DataTable();
  resultsTable.clear().draw();
}

// Function to handle displaying results in the DataTable
function displayResults(result) {
  var t = $('#scanResults').DataTable();
  if (result && result.ip_address && result.mac_address) {
    t.row.add([
      result.ip_address,
      result.mac_address
    ]).draw(false);
    $('#resultsCard').css('display', 'block');
  } else {
    console.error('Result is not in the expected format:', result);
  }
}

// Event listener for ARP scan result
event.listen('arp-scan-result', (event) => {
  console.log('Received rust-message event:', event);
  displayResults(event.payload);
});

// Event listener for the scan button
document.getElementById('scanButton').addEventListener('click', function () {
  const interfaceName = document.getElementById('interfaceName').value;
  const sourceIp = document.getElementById('sourceIp').value;
  const subnet = document.getElementById('subnet').value;

  clearResults();
  invoke('arp_scan', { interfaceName, sourceIp, subnet }).catch(displayError);
});

// Initialization of the DataTable and populating the interface dropdown
$(document).ready(function() {
  $('#scanResults').DataTable({
    columns: [
      { title: "IP Address" },
      { title: "MAC Address" }
    ]
  });

  populateInterfaceDropdown();
});
