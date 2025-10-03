const label = document.querySelector('label[for="id_username"]');
if (label?.textContent.trim().toLowerCase() === "username") {
  label.textContent = "E-mail address:";
}

const inputName = document.querySelector('input[name="username"]');
if (inputName) {
  inputName.classList.add("input");
  inputName.setAttribute("type", "email");
  inputName.setAttribute("placeholder", "E-mail address");
}

const inputPassword = document.querySelector('input[name="password"]');
if (inputPassword) {
  inputPassword.classList.add("input");
}