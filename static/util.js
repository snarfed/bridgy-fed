// Handles state of login buttons and input fields on the settings page.
var openedId;

// Grabs existing object of disabled checkboxes or creates a new one
var disabledCheckboxes = getDisabledCheckboxes();

 // Clear the auth_entity query param on /settings.
window.onload = function () {
  url = new URL(window.document.documentURI)
  if (url.pathname == '/settings' && url.searchParams.has('auth_entity')) {
    window.history.replaceState(null, '', '/settings')
  }

  // Updates disabled states for bridging checkboxes
  for (const [key, value] of Object.entries(disabledCheckboxes)) {
    if (new Date().getTime() > value) {
      delete disabledCheckboxes[key];
    } else {
      var checkbox = document.getElementById(key);
      if (checkbox) {
        checkbox.disabled = true;

        document.getElementById(key + "-wrapper").style.opacity = 0.2;

        var disabledNotice = document.getElementById(key + "-disabled-notice");
        var timeLeft = Math.ceil((value - new Date().getTime()) / 60000);
        disabledNotice.textContent += "Processing. Can change bridging status in " + timeLeft + " minutes.";
        disabledNotice.style.display = "block";
      }
    }
  }

  localStorage.setItem('disabledCheckboxes', JSON.stringify(disabledCheckboxes));

  // Unhides Threads login if feature flag is enabled.
  if (window.location.pathname == '/login') {
    var urlParams = new URLSearchParams(window.location.search);

    if (urlParams.get('enable-threads') == 'true') {
      document.getElementById('threads-form').style.display = 'block';
    }
  }
}

// Handles login buttons and input fields on the settings page.
function toggleInput(button_id) {
  var button = document.getElementById(button_id);
  var input = document.getElementById(button_id + "-input");
  var submit = document.getElementById(button_id + "-submit");
  
  if (openedId && openedId != button_id) {
    document.getElementById(openedId).classList.remove("slide-up");

    document.getElementById(openedId + "-submit").classList.remove("visible");
    document.getElementById(openedId + "-input").classList.remove("visible");

    openedId = null;
  }

  if(input.classList.contains("visible")){
    submit.classList.remove("visible");
    input.classList.remove("visible");

    button.classList.remove("slide-up");

    openedId = null;
  } else {
    openedId = button_id;

    button.classList.add("slide-up");

    submit.classList.add("visible");
    input.classList.add("visible");
    input.focus();
  }
}

// Used on setting page to change an account's bridging state.
function bridgingSwitch(event) {
  const checkbox = event.currentTarget;
  disableCheckbox(checkbox);
  event.currentTarget.closest('form').submit()
}

// Temporarily disable the bridging switch to avoid double submission
function disableCheckbox(checkbox) {
  checkbox.disabled = true;

  // Disable the checkbox for 5 minutes
  disabledCheckboxes[checkbox.id] = new Date().getTime() + 300000;
  localStorage.setItem('disabledCheckboxes', JSON.stringify(disabledCheckboxes));
}

// Grabs existing object of disabled checkboxes or creates a new one
function getDisabledCheckboxes() {
  var disabledCheckboxesString = localStorage.getItem('disabledCheckboxes');

  var disabledCheckboxes;

  if (disabledCheckboxesString && disabledCheckboxesString != '{}') {
    disabledCheckboxes = JSON.parse(disabledCheckboxesString);
  } else {
    disabledCheckboxes = new Object();
  }

  return disabledCheckboxes;
}