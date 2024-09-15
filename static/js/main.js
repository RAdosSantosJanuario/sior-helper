document.addEventListener('DOMContentLoaded', function () {
  fetchFileModificationTime();
  updateTaskList();
  setInterval(updateTaskList, 15000);

  const showEmailBtn = document.getElementById('show-email-btn');
  if (showEmailBtn) {
    showEmailBtn.addEventListener('click', function () {
      fetch('/get_email')
        .then(response => response.json())
        .then(data => {
          document.getElementById('email').textContent = data.email;
          document.getElementById('email').style.display = 'block';
          this.style.display = 'none';
        });
    });
  }


  const loadModalButtons = document.querySelectorAll(".load-details-btn");
  if (loadModalButtons) {
    loadModalButtons.forEach(button => {
      button.addEventListener("click", function () {
        const techniqueId = this.getAttribute("data-technique-id");
        const taskId = this.getAttribute("data-task-id");
        loadTechniquePage(techniqueId, taskId);
      });
    });
  }

  document.querySelectorAll(".downloadRunButton").forEach(button => {
    button.addEventListener('click', function () {
      const taskId = this.getAttribute('data-task-id');
      downloadRun(taskId);
      showSnackbar('Starting download for run');
    });
  });

  //document.querySelectorAll(".downloadHeatMapUsageButton").forEach(button => {
  //  button.addEventListener('click', function () {
  //    const taskId = this.getAttribute('data-task-id');
  //    downloadHeatMapUsage(taskId);
  //    showSnackbar('You can import the result here: https://mitre-attack.github.io/attack-navigator/ to see the heat-map');
  //  });
  //});

  document.querySelectorAll(".downloadHeatMapButton").forEach(button => {
    button.addEventListener('click', function () {
      const taskId = this.getAttribute('data-task-id');
      downloadHeatMap(taskId);
      showSnackbar('You can import the result here: https://mitre-attack.github.io/attack-navigator/ to see the heat-map');
    });
  });

  const firstTabEl = document.querySelector('#detailTabs .nav-link.active')
  if (firstTabEl) {
    var firstTab = new bootstrap.Tab(firstTabEl)
    firstTab.show()
  }

  const taskListToggle = document.getElementById("taskListToggle");
  if (taskListToggle) {
    taskListToggle.addEventListener('click', function () {
      updateTaskList();
    });
  }

  const modalButton = document.getElementById("refreshButton");
  if (modalButton) {
    modalButton.addEventListener('click', function () {
      updateTaskList();
    });
  }

  const clearButton = document.getElementById("clearButton");
  if (clearButton) {
    clearButton.addEventListener('click', function () {
      clearDeletedAndAbortedTasks();
    });
  }

  const runCache = document.getElementById("runCache");
  if (runCache) {
    runCache.addEventListener('click', function () {
      runUpdateCache();
      showSnackbar("Started Update Cache");
    });
  }
});

$(document).ready(function () {
  $.fn.dataTable.moment('DD-MM-YYYY HH:mm:ss');

  $('#taskListModal').on('show.bs.modal', function () {
    updateTaskList();
  });

  $.ajaxSetup({
    beforeSend: function (xhr, settings) {
      if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
        xhr.setRequestHeader("X-CSRFToken", $('meta[name="csrf-token"]').attr('content'));
      }
    }
  });

  var table = $('#evaluation_table').DataTable({
    ajax: {
      url: '/api/runs',
      type: 'GET',
      dataSrc: ''
    },
    columns: [
      { data: 'created_run' },
      { data: 'created_by.username' },
      {
        data: 'interrelation_keywords_and_groups',
        render: function (data, type, row) {
          return data !== 'SINGLE' ? data : '';
        }
      },
      {
        data: 'keywords',
        render: function (data, type, row) {
          return data.join(", ");
        }
      },
      {
        data: 'interrelation_keywords',
        render: function (data, type, row) {
          return data !== 'SINGLE' ? data : '';
        }
      },
      {
        data: 'groups',
        render: function (data, type, row) {
          return data.join(", ");
        }
      },
      {
        data: 'interrelation_groups',
        render: function (data, type, row) {
          return data !== 'SINGLE' ? data : '';
        }
      },
      {
        data: 'stats.total_used_techniques',
      },
      {
        data: null,
        render: function (data, type, row) {
          let techniquesUrl = `/techniques/${row.task_id}`;
          let actionHtml = `<td class="multi-td" style="justify-content: center !important;">
                          <a class="btn btn-outline-secondary btn-small me-1" href="${techniquesUrl}" title="Open details for this evaluation"><i class="material-icons">open_in_new</i></a>`;
          let deleteTechniquesUrl = `/deletetechnique/${row.task_id}`;
          let csrfToken = $('meta[name="csrf-token"]').attr('content');
          if (row.is_authorized) {
            actionHtml += `<form class="run-script-form d-inline me-1" action="/run-script" method="post">
                          <input type="hidden" name="csrf_token" value="${csrfToken}"/>
                          ${row.keywords.map(keyword => `<input type="hidden" name="keywords_input" value="${keyword}" required>`).join('')}
                          ${row.groups.map(group => `<input type="hidden" name="groupSelect" value="${group}" required>`).join('')}
                          <input type="hidden" name="interrelation_keywords_and_groups" value="${row.interrelation_keywords_and_groups}" required>
                          <input type="hidden" name="interrelation_keywords" value="${row.interrelation_keywords}" required>
                          <input type="hidden" name="interrelation_groups" value="${row.interrelation_groups}" required>
                          <button class="btn btn-outline-secondary btn-small" type="submit" title="Restart evaluation">
                              <i class="material-icons">replay</i>
                          </button>
                      </form>
                      <form class="delete-form d-inline me-1" action="${deleteTechniquesUrl}" method="post">
                          <input type="hidden" name="csrf_token" value="${csrfToken}"/>
                          <button class='btn btn-outline-danger btn-small' type="submit" title="Delete this evaluation"><i class="material-icons">delete</i></button>
                      </form>`;
          }

          actionHtml += '</td>';

          return actionHtml;
        },
        className: "text-center"
      }
    ],
    responsive: true,
    autoWidth: false,
    columnDefs: [
      { targets: [1, 2, 4, 6], className: "text-center", searchable: true },
      { targets: [3, 5, 7], className: "text-center", searchable: false },
      { targets: [3], type: "date-custom" }
    ],
    order: [[0, 'desc']],
    drawCallback: function () {
      attachFormSubmitHandlers(table);
    }
  });


  $('.dropdown').hover(function () {
    $('.dropdown-menu', this).not('.in .dropdown-menu').stop(true, true).slideDown("400");
    $(this).toggleClass('open');
  }, function () {
    $('.dropdown-menu', this).not('.in .dropdown-menu').stop(true, true).slideUp("400");
    $(this).toggleClass('open');
  });

  const groupSelect = $('#groupSelect').select2({
    placeholder: 'Select groups',
    ajax: {
      url: '/api/groups',
      dataType: 'json',
      delay: 250,
      data: function (params) {
        return {
          search: params.term
        };
      },
      processResults: function (data) {
        return {
          results: data.map(function (item) {
            return { id: item.name, text: item.name };
          })
        };
      },
      cache: true
    },
    minimumInputLength: 2
  });
  groupSelect.on("select2:select select2:unselect", function (e) {
    updateAssociationModeVisibility('#groupSelect', 'groupAssociationModeSection');
  });

  const keywordSelect = $('.keywords-select').select2({
    tags: true,
    tokenSeparators: [','],
    placeholder: "Enter keywords separated by commas"
  });
  keywordSelect.on("select2:select select2:unselect", function (e) {
    updateAssociationModeVisibility('#keywords_input', 'keywordAssociationModeSection');
  });

  $('.run-script-form').each(function () {
    $(this).on('submit', function (event) {
      event.preventDefault();

      const form = $(this);
      form.find(':submit').attr('disabled', 'disabled');

      $.ajax({
        url: form.attr('action'),
        type: 'POST',
        data: form.serialize(),
        success: function (response) {
          if (response.status == 'PARAMETERS_EMPTY') {
            alert('Keywords and groups empty, please add on of them.');
            form.find(':submit').removeAttr('disabled');
          } else if (response.status == 'EXIST') {
            $('#existingRunDate').text(response.created_run);
            $('#confirmationModal').modal('show');

            $('#confirmRun').one('click', function () {
              form.append('<input type="hidden" name="force_run" value="true">');

              $.ajax({
                url: form.attr('action'),
                type: 'POST',
                data: form.serialize(),
                success: function (secondResponse) {
                  $('#confirmationModal').modal('hide');
                  if (secondResponse.task_id) {
                    $('#loader').show();
                    showSnackbar("Added run to queue");
                    const taskId = secondResponse.task_id;
                    checkRunStatus(taskId, form, table);
                  } else {
                    alert('Task ID not found in response. Please try again.');
                    form.find(':submit').removeAttr('disabled');
                  }
                },
                error: function () {
                  $('#loader').hide();
                  form.find(':submit').removeAttr('disabled');
                  alert('An error occurred. Please try again.');
                }
              });
            });

            form.find(':submit').removeAttr('disabled');
          } else {
            $('#loader').show();
            showSnackbar("Added run to queue");
            const taskId = response.task_id;
            checkRunStatus(taskId, form, table);
          }
        },
        error: function () {
          $('#loader').hide();
          form.find(':submit').removeAttr('disabled');
          alert('An error occurred. Please try again.');
        }
      });
    });
  });

  $('#technique_table').DataTable({
    responsive: {
      breakpoints: [
        { name: 'bigdesktop', width: Infinity },
        { name: 'meddesktop', width: 1480 },
        { name: 'smalldesktop', width: 1280 },
        { name: 'medium', width: 1188 },
        { name: 'tabletl', width: 1024 },
        { name: 'btwtabllandp', width: 848 },
        { name: 'tabletp', width: 768 },
        { name: 'mobilel', width: 480 },
        { name: 'mobilep', width: 320 }
      ]
    },
    autoWidth: false,
    columnDefs: [{ targets: [2, 3, 4], className: 'text-center', searchable: false }],
    order: [
      [2, 'desc'],
      [4, 'desc'],
      [3, 'desc']
    ]
  })
});



function downloadRun(taskId) {
  window.location.href = `/download-run/${taskId}`
}

function downloadHeatMapUsage(taskId) {
  window.location.href = `/download-heatmap-usage/${taskId}`;
}

function downloadHeatMap(taskId) {
  window.location.href = `/download-heatmap/${taskId}`;
}

function fetchFileModificationTime() {
  fileModTime = document.getElementById('fileModTime');
  if (fileModTime) {
    fetch(`/api/last-cache-check`)
      .then(response => response.json())
      .then(data => {
        if (data.status === 'success') {
          fileModTime.textContent = 'Cache last updated: ' + data.mod_time;
        } else {
          fileModTime.textContent = 'No cache available'
        }
      })
      .catch(error => {
        fileModTime.textContent = 'Error fetching data.';
      });
  }
}

let previousTasks = [];

function updateTaskList() {
  fetch('/tasks')
    .then(response => response.json())
    .then(tasks => {
      if (JSON.stringify(tasks) === JSON.stringify(previousTasks)) {
        return;
      }
      previousTasks = tasks;
      const taskTableBody = document.getElementById('taskTableBody');
      if (!taskTableBody) {
        return;
      }
      taskTableBody.innerHTML = '';
      tasks.forEach(task => {
        let row = document.createElement('tr');
        row.innerHTML = `
          <td>${task.id}</td>
          <td>${task.state}</td>
          <td>${task.created_run}</td>
        `;
        taskTableBody.appendChild(row);
      });
    })
    .catch(error => {
      return
    });
}


function runUpdateCache() {
  fetch(`/api/run-cache`)
    .then(response => response.json())
    .catch(error => {
      console.log("error while getting cache: ", error)
    });
}


function showSnackbar(text) {
  var x = document.getElementById("snackbar");
  x.className = "show";
  document.getElementById('snackbar').textContent = text;
  setTimeout(function () { x.className = x.className.replace("show", ""); }, 4000);
}


function updateAssociationModeVisibility(containerId, associationSectionId) {
  var $select = $(containerId);
  var count = $select.select2('data').length;
  const associationSection = document.getElementById(associationSectionId);
  if (count > 1) {
    associationSection.style.display = 'block';
    $(associationSectionId).collapse('show');
  } else {
    associationSection.style.display = 'none';
    $(associationSectionId).collapse('hide');
  }
}

function loadTechniquePage(techniqueId, taskId) {
  window.location.href = `/technique-details/${techniqueId}/${taskId}`;
}

function attachFormSubmitHandlers(table) {
  $('.run-script-form').off('submit').on('submit', function (event) {
    event.preventDefault();

    const form = $(this);
    form.find(':submit').attr('disabled', 'disabled');

    $.ajax({
      url: form.attr('action'),
      type: 'POST',
      data: form.serialize(),
      success: function (response) {
        if (response.status == 'PARAMETERS_EMPTY') {
          alert('Keywords and groups empty, please add one of them.');
          form.find(':submit').removeAttr('disabled');
        } else if (response.status == 'EXIST') {
          $('#existingRunDate').text(response.created_run);
          $('#confirmationModal').modal('show');

          $('#confirmRun').one('click', function () {
            form.append('<input type="hidden" name="force_run" value="true">');

            $.ajax({
              url: form.attr('action'),
              type: 'POST',
              data: form.serialize(),
              success: function (secondResponse) {
                $('#confirmationModal').modal('hide');
                if (secondResponse.task_id) {
                  $('#loader').show();
                  showSnackbar("Added run to queue");
                  const taskId = secondResponse.task_id;
                  checkRunStatus(taskId, form, table);
                } else {
                  alert('Task ID not found in response. Please try again.');
                  form.find(':submit').removeAttr('disabled');
                }
              },
              error: function () {
                $('#loader').hide();
                form.find(':submit').removeAttr('disabled');
                alert('An error occurred. Please try again.');
              }
            });
          });

          form.find(':submit').removeAttr('disabled');
        } else {
          $('#loader').show();
          showSnackbar("Added run to queue");
          const taskId = response.task_id;
          checkRunStatus(taskId, form, table);
        }
      },
      error: function () {
        $('#loader').hide();
        form.find(':submit').removeAttr('disabled');
        alert('An error occurred. Please try again.');
      }
    });
  });

  $(document).off('submit', '.delete-form').on('submit', '.delete-form', function (event) {
    event.preventDefault();

    const form = $(this);
    form.find(':submit').attr('disabled', 'disabled');

    $.ajax({
      url: form.attr('action'),
      type: 'POST',
      data: form.serialize(),
      success: function (response) {
        table.ajax.reload(null, false);
        form.find(':submit').removeAttr('disabled');
        console.log("Delete successful:", response);
      },
      error: function (xhr, status, error) {
        console.error("Delete operation failed:", xhr, status, error);
        form.find(':submit').removeAttr('disabled');
      }
    });
  });
}

function checkRunStatus(taskId, form, table) {
  $.ajax({
    url: '/run-status/' + taskId,
    type: 'GET',
    success: function (response) {
      if (response.state === 'PENDING' || response.state === 'STARTED') {
        setTimeout(function () {
          checkRunStatus(taskId, form, table);
        }, 250);
      } else {
        form.find(':submit').removeAttr('disabled');
        if (response.state === 'SUCCESS') {
          $('#loader').hide();
          if (response.status === 'NO_TECHNIQUES') {
            alert("Could not find any techniques for your request");
          } else {
            table.ajax.reload(null, false)
            $('#groupSelect, #keywords_input').val(null).trigger('change');
            document.getElementById('keywordAssociationModeSection').style.display = 'none';
            document.getElementById('groupAssociationModeSection').style.display = 'none';
          }
        } else {
          alert(response);
        }
      }
    },
    error: function (xhr, status, error) {
      $('#loader').hide();
      form.find(':submit').removeAttr('disabled');
      console.error('Error occurred:', error);
      alert('An error occurred. Please try again.');
    }
  });
}


