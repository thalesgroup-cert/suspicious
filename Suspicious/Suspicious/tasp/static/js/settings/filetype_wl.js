function showFeedback(input, message, type) {
  const feedback = input.nextElementSibling;
  feedback.textContent = message;
  feedback.classList.add(type, "button");
  setTimeout(() => {
    feedback.textContent =
      input.id === "file-filetype" ? "Add from file" : "Add filetype(s)";
    feedback.classList.remove(type, "button");
    if (input.type === "file") input.value = "";
  }, 3000);
}

function createDivftwl(id, type) {
  const div = document.createElement('div');
  div.classList.add(type+'List');
  div.id = 'div-' + id;
  const p = document.createElement('p');
  p.id = id;
  const icon = document.createElement('i');
  if (type === 'filetype') {
    p.classList.add('allFiletypes');
    icon.classList.add('fas', 'fa-file');
  }
  p.appendChild(icon);
  p.appendChild(document.createTextNode(` ${id}`));
  div.appendChild(p);
  const buttonDiv = document.createElement('div');
  buttonDiv.classList.add(type);
  buttonDiv.id = 'buttonDiv-' + id;
  const button = document.createElement('button');
  button.classList.add('button', 'is-danger', 'ddB');
  button.id = `button_${id}`;
  button.type = 'submit';
  button.textContent = 'Remove';
  if (type === 'filetype') {
    button.addEventListener('click', function() {
      removeFiletype(id);
    });
  }
  buttonDiv.appendChild(button);
  div.appendChild(buttonDiv);
  return div;
}

function addFiletype() {
  const input = document.getElementById("id_filetype");
  const filetypes = input.value.split(/[ ,;]/).filter(Boolean);
  input.value = "";

  const existingFiletypes = Array.from(
    document.querySelectorAll(".allFiletypes")
  ).map((el) => el.innerHTML.replace('<i class="fas fa-globe"></i> ', ""));

  filetypes.forEach((filetype) => {
    if (existingFiletypes.includes(filetype)) {
      showFeedback(input, "filetype already listed", "is-danger");
      return;
    }
    if (filetype === "") {
      showFeedback(input, "Please enter a filetype", "is-danger");
      return;
    }

    fetch(`../add-filetype/${filetype}`)
      .then((res) => res.json())
      .then((result) => {
        if (result.success) {
          showFeedback(input, "New filetypes added!", "is-success");
          const div = createDivftwl(result.filetype, "filetype");
          document.getElementById("list-filetype").appendChild(div);
          change();
        } else {
          showFeedback(input, result.message, "is-danger");
        }
      });
  });
}

function addFiletypes() {
  const input = document.getElementById("file-filetype");
  const file = input.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append("file", file);

  fetch("../add-filetype-file/", {
    method: "POST",
    body: formData,
  })
    .then((res) => res.json())
    .then((result) => {
      if (result.success) {
        const filetypes = result.filetypes || [];
        const message =
          filetypes.length === 0
            ? "No good filetypes in file."
            : `${result.filetype_added_num} filetypes added !`;
        showFeedback(
          input,
          message,
          filetypes.length ? "is-success" : "is-danger"
        );

        filetypes.forEach((ft) => {
          if (!ft.trim()) return;
          const div = createDivftwl(ft, "filetype");
          document.getElementById("list-filetype").appendChild(div);
          change();
        });
      } else {
        showFeedback(input, result.message, "is-danger");
      }
    });
}

function removeFiletype(filetype) {
  fetch(`../remove-filetype/${filetype}`)
    .then((res) => res.json())
    .then((result) => {
      if (result.success) {
        document.getElementById(`buttonDiv-${filetype}`)?.remove();
        document.getElementById(`div-${filetype}`)?.remove();
        change();
      }
    });
}
