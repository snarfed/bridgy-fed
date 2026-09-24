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

  // Localizes embedded posts' published times
  for (const time of document.querySelectorAll('.post-embed time.dt-published[datetime]')) {
    time.textContent = new Date(time.getAttribute('datetime')).toLocaleString(
      undefined, {dateStyle: 'medium', timeStyle: 'short'});
  }
}

// Focuses a login button's input when its <details> opens. toggle doesn't
// bubble, so this listens in the capture phase.
document.addEventListener('toggle', (event) => {
  if (event.target.name == 'login' && event.target.open) {
    event.target.querySelector('input')?.focus();
  }
}, true);

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

// Copies an element's data-copy attribute to the clipboard when it's clicked.
document.addEventListener('click', (event) => {
  const elem = event.target.closest('[data-copy]');
  if (elem) {
    navigator.clipboard.writeText(elem.dataset.copy)
    document.getElementById('messages').innerHTML = `<div class="message shadow">Copied <em>${elem.dataset.copy}</em> to the clipboard.</div>`
  }
});
