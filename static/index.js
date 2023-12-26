/**
 * Code for the home page protocol picker.
 */

function update() {
  // show matching instructions
  // console.log($('.instruction'))

  let showed = false;
  for (instr of $('.instruction')) {
    let parts = instr.id.split('-')
    let me = parts[1]
    let them = parts[2]
    // console.log(me, them, $(`#me-${me}`)[0].checked, $(`#them-${them}`)[0].checked)

    if ($(`#me-${me}`)[0].checked && $(`#them-${them}`)[0].checked) {
      instr.style.display = 'block'
      document.getElementById('front-instructions')
        .scrollIntoView({behavior: 'smooth', block: 'nearest'})
      showed = true;
    } else {
      instr.style.display = 'none'
    }
  }

  document.getElementById('front-instruction-placeholder').style.display =
    (showed) ? 'none' : 'block'
}

// addEventListener('DOMContentLoaded', () => {
//   $('input').on('change', update)
// })
