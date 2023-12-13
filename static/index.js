/**
 * Code for the home page protocol picker.
 */

function update() {
  // show matching instructions
  // console.log($('.instruction'))
  for (instr of $('.instruction')) {
    if (instr.id == 'front-instruction-placeholder') {
      instr.style.display = 'none'
      continue
    }

    let parts = instr.id.split('-')
    let me = parts[1]
    let them = parts[2]
    // console.log(me, them, $(`#me-${me}`)[0].checked, $(`#them-${them}`)[0].checked)
    instr.style.display =
      ($(`#me-${me}`)[0].checked && $(`#them-${them}`)[0].checked)
      ? 'block' : 'none'
  }
}

addEventListener('DOMContentLoaded', () => {
  $('input').on('change', update)
})
