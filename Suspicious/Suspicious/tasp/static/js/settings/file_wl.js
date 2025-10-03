function showFeedback(input, message, type = "is-success", resetText = "", isFile = false) {
  const feedback = input.nextElementSibling;
  feedback.textContent = message;
  feedback.classList.add(type, "button");

  setTimeout(() => {
    feedback.textContent = resetText;
    feedback.classList.remove(type, "button");
    if (isFile) input.value = "";
  }, 3000);
}


function createDivfwl(id, type) {
  const div = document.createElement('div');
  div.classList.add(type+'List');
  div.id = 'div-' + id;
  const p = document.createElement('p');
  p.id = id;
  const icon = document.createElement('i');
  if (type === 'file') {
    p.classList.add('allFiles');
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
  if (type === 'file') {
    button.addEventListener('click', function() {
      removeFile(id);
    });
  }
  buttonDiv.appendChild(button);
  div.appendChild(buttonDiv);
  return div;
}


async function addFile() {
  const input = document.getElementById('id_file');
  const files = input.value.split(/[ ,;]/).filter(Boolean);
  const existingFiles = Array.from(document.querySelectorAll('.allfiles'))
    .map(f => f.innerHTML.replace('<i class="fas fa-globe"></i> ', ''));

  input.value = '';

  for (const file of files) {
    if (file === '') {
      showFeedback(input, 'Please enter a file hash', 'is-danger', 'Add file(s)');
      continue;
    }
    if (existingFiles.includes(file)) {
      showFeedback(input, 'File already listed', 'is-danger', 'Add file(s)');
      continue;
    }
    try {
      const response = await fetch(`../add-file/${encodeURIComponent(file)}`);
      const result = await response.json();

      if (result.success) {
        showFeedback(input, 'New files added!', 'is-success', 'Add file(s)');
        const div = createDivfwl(result.file, 'file');
        document.getElementById('list-file').appendChild(div);
        change();
      } else {
        showFeedback(input, result.message || 'Error adding file', 'is-danger', 'Add file(s)');
      }
    } catch (error) {
      showFeedback(input, 'Network error', 'is-danger', 'Add file(s)');
      console.error('Error adding file:', error);
    }
  }
}

async function addFiles() {
  const fileInput = document.getElementById('file');
  if (fileInput.files.length === 0) return;

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);

  try {
    const response = await fetch('../add-file-by-upload/', {
      method: 'POST',
      body: formData
    });
    const result = await response.json();

    if (result.success) {
      const file = result.file.trim();
      if (file === "") {
        showFeedback(fileInput, 'Error in file.', 'is-danger', 'Add from file', true);
      } else {
        showFeedback(fileInput, 'File added to AllowList !', 'is-success', 'Add from file', true);
        const div = createDivfwl(file, 'file');
        document.getElementById('list-file').appendChild(div);
        change();
      }
    } else {
      showFeedback(fileInput, result.message || 'Error processing file', 'is-danger', 'Add from file', true);
    }
  } catch (error) {
    showFeedback(fileInput, 'Network error', 'is-danger', 'Add from file', true);
    console.error('Error adding files from upload:', error);
  }
}

async function removeFile(file) {
  try {
    const response = await fetch(`../remove-file/${encodeURIComponent(file)}`);
    const result = await response.json();

    if (result.success) {
      document.getElementById(`buttonDiv-${file}`)?.remove();
      document.getElementById(`div-${file}`)?.remove();
      change();
    }
  } catch (error) {
    const input = document.getElementById('id_file') || document.getElementById('file');
    if (input) {
      showFeedback(input, 'Network error while removing file', 'is-danger', '', false);
    }
    console.error('Error removing file:', error);
  }
}
