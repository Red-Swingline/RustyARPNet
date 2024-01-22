const {invoke, event} = window.__TAURI__;

// Function to populate the interface dropdown
function populateInterfaceDropdown() {
    invoke('get_network_interfaces').then(interfaceNames => {
        const interfaceSelect = document.getElementById('interfaceName');
        interfaceSelect.innerHTML = ''; // Clear the dropdown before populating
        interfaceNames.forEach(name => {
            const option = document.createElement('option');
            option.value = name;
            option.textContent = name;
            interfaceSelect.appendChild(option);
        });
    }).catch(displayError);
}

// Function to display error messages
function displayError(error) {
    const resultsElement = document.getElementById('scanResults');
    const errorDiv = document.createElement('div');
    errorDiv.textContent = `Error: ${error}`;
    errorDiv.className = 'error'; // Add a class for styling if needed
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
      let scanButtonHtml = `<button class="port-scan-btn" data-ip="${result.ip_address}">Scan Ports</button>`;
      // Add empty string for the details-control column
      t.row.add(['', scanButtonHtml, result.ip_address, result.mac_address]).draw(false);
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
// Event listener for port scan result
event.listen('port-scan-result', (event) => {
  console.log('Received port-scan-result event:', event);
  // Find the row with the matching IP address and update it
  let rowData = findRowByIp(event.payload.ip_address);
  if (rowData) {
      let table = $('#scanResults').DataTable();
      let tr = $(rowData.node());
      let row = table.row(tr);
      if (row.child.isShown()) {
          row.child(format(event.payload)).show();
      }
  }
});

// Event listener for the scan button
document.getElementById('scanButton').addEventListener('click', function () {
    const interfaceName = document.getElementById('interfaceName').value;
    const sourceIp = document.getElementById('sourceIp').value;
    const subnet = document.getElementById('subnet').value;

    clearResults();
    invoke('arp_scan', {interfaceName, sourceIp, subnet}).catch(displayError);
});

// Initialization of the DataTable with an extra column for actions
$(document).ready(function () {
  // Initialize the DataTable with the new details-control column
  let table = $('#scanResults').DataTable({
      'columns': [
          {
              'className': 'details-control',
              'orderable': false,
              'data': null,
              'defaultContent': '<i class="fa fa-plus-square" aria-hidden="true"></i>'
          },
          { 'title': "Actions", 'orderable': false },
          { 'title': "IP Address" },
          { 'title': "MAC Address" }
      ],
      'order': [[2, 'asc']]
  });

  // Event listener for opening and closing details
  $('#scanResults tbody').on('click', 'td.details-control', function () {
      var tr = $(this).closest('tr');
      var row = table.row(tr);

      if (row.child.isShown()) {
          row.child.hide();
          tr.removeClass('shown');
          $(this).html('<i class="fa fa-plus-square" aria-hidden="true"></i>'); 
      } else {
          row.child(format(row.data())).show();
          tr.addClass('shown');
          $(this).html('<i class="fa fa-minus-square" aria-hidden="true"></i>');
      }
  });

  // Event listener for dynamically created port scan buttons
  $('#scanResults tbody').on('click', '.port-scan-btn', function () {
      let ip = $(this).data('ip');
      let interfaceName = $('#interfaceName').val();

      console.log('Initiating port scan for IP:', ip);
      $(this).prop('disabled', true); 

      // Invoke the Tauri command for port scanning
      invoke('scan_ports_for_ip', {
          interface_name: interfaceName,
          ip_address: ip,
          scan_common: true 
      }).then(ports => {
          console.log('Open ports:', ports);
          $(this).prop('disabled', false); 
      }).catch(error => {
          console.error('Error during port scan:', error);
          displayError(error);
          $(this).prop('disabled', false);
      });
  });

  populateInterfaceDropdown(); 
});

// Formatting function for row details
function format(d) {
  // d is the data object for the row
  return `<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">
      <tr>
          <td>Port scan results:</td>
          <td>${d.open_ports ? d.open_ports.join(", ") : ''}</td>
      </tr>
  </table>`;
}
// Helper function to find the row by IP address
function findRowByIp(ipAddress) {
  let table = $('#scanResults').DataTable();
  return table.rows().eq(0).filter(function (idx) {
      let data = table.row(idx).data();
      return data && data[2] === ipAddress;
  }).any() ? table.row(function (idx, data, node) {
      return data[2] === ipAddress;
  }) : null;
}