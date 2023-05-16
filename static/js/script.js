function copySecret() {
    /* Get the text field */
    var copyText = document.getElementById("secret");

    /* Select the text field */
    copyText.select();
    copyText.setSelectionRange(0, 99999); /*For mobile devices*/

    /* Copy the text inside the text field */
    document.execCommand("copy");

    alert("Successfully copied TOTP secret token!");
 }


var password = document.getElementById("password")
var confirm_password = document.getElementById("confirm_password");

function validatePassword(){
  if(password.value != confirm_password.value) {
    confirm_password.setCustomValidity("Passwords Don't Match");
  } else {
    confirm_password.setCustomValidity('');
  }
}

if (password != null)
    password.onchange = validatePassword;
if (confirm_password != null)
    confirm_password.onkeyup = validatePassword;