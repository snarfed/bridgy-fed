/**
 * Clear the auth_entity query param on /settings.
 */

window.onload = function () {
  url = new URL(window.document.documentURI)
  if (url.pathname == '/settings' && url.searchParams.has('auth_entity')) {
    window.history.replaceState(null, '', '/settings')
  }
}

function bridgingSwitch(event) {
  const checkbox = event.currentTarget;
  event.currentTarget.closest('form').submit()
}
