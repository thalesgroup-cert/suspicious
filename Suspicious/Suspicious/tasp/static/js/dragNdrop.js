document.addEventListener('DOMContentLoaded', () => {
  const fileInput   = document.getElementById('id_file');
  const urlInput    = document.getElementById('id_url');
  const otherInput  = document.getElementById('id_other');
  const fileResult  = document.getElementById('file-result');
  const fileSubmit  = document.getElementById('submit');
  const urlSubmit   = document.getElementById('submit-url');
  const otherSubmit = document.getElementById('submit-other');
  const dropZone    = document.getElementById('Files');

  hideAllLabels();
  styleInputs();
  switchTab('Other');
  setButtonsDisabled([fileSubmit, urlSubmit, otherSubmit], true);

  // Delegate clicks
  document.addEventListener('click', (e) => {
    if (e.target.matches('.js-modal-triggers')) {
      const modal = document.getElementById(e.target.dataset.target);
      modal?.classList.add('is-active');
    }
    if (dropZone?.contains(e.target) && e.target.tagName !== 'BUTTON') {
      fileInput?.click();
    }
  });

  document.addEventListener('input', (e) => {
    if (e.target === otherInput) {
      otherSubmit.disabled = !e.target.value.trim();
    }
    if (e.target === urlInput) {
      urlSubmit.disabled = !e.target.value.trim();
    }
  });

  document.addEventListener('change', (e) => {
    if (e.target === fileInput) {
      handleFileSelection();
      if (fileInput.files.length) {
        updateThumbnail(dropZone, fileInput.files[0]);
      }
    }
  });

  // Drag & drop
  ['dragover', 'dragleave', 'dragend', 'drop'].forEach((eventName) => {
    window.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone?.classList.toggle('drop-zone--over', eventName === 'dragover');
    });
  });

  window.addEventListener('drop', (e) => {
    if (e.dataTransfer?.files?.length) {
      fileInput.files = e.dataTransfer.files;
      updateThumbnail(dropZone, e.dataTransfer.files[0]);
    }
  });

  // Functions
  function hideAllLabels() {
    document.querySelectorAll('label').forEach((lbl) => lbl.style.display = 'none');
  }

  function styleInputs() {
    if (urlInput) {
      urlInput.classList.add('input');
      urlInput.setAttribute('placeholder', 'Enter a valid URL...');
    }
    if (otherInput){
      otherInput.classList.add('input');
      otherInput.setAttribute('placeholder', 'Enter a valid Hash or IP...');
    }

    if (fileInput) {
      fileInput.classList.add('file-input');
    }
  }

  function switchTab(tabName) {
    document.querySelectorAll('.tabcontent').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.tabslinks').forEach(el => el.classList.remove('is-active'));

    const content = document.getElementById(tabName);
    const link = document.getElementById(tabName.toUpperCase());
    if (content) content.style.display = 'block';
    if (link) link.classList.add('is-active');
  }


  function setButtonsDisabled(buttons, disabled) {
    buttons.forEach(btn => btn.disabled = disabled);
  }

  function handleFileSelection() {
    if (!fileInput || !fileInput.files.length) {
      fileResult.textContent = '';
      fileSubmit.disabled = true;
      return;
    }
    const file = fileInput.files[0];
    const fileMb = file.size / (1024 ** 2);
    if (fileMb >= 50) {
      fileResult.textContent = 'Please select a file less than 50MB.';
      fileSubmit.disabled = true;
    } else {
      fileResult.textContent = `File size: ${fileMb.toFixed(1)} MB.`;
      fileSubmit.disabled = false;
    }
  }

  function updateThumbnail(dropZoneEl, file) {
    if (!dropZoneEl) return;
    dropZoneEl.querySelector('.drop-zone__prompt')?.remove();

    let thumb = dropZoneEl.querySelector('.drop-zone__thumb');
    if (!thumb) {
      thumb = document.createElement('div');
      thumb.classList.add('drop-zone__thumb');
      dropZoneEl.appendChild(thumb);
    }

    thumb.dataset.label = file.name;
    fileSubmit.disabled = false;

    if (file.type.startsWith('image/')) {
      const reader = new FileReader();
      reader.onload = () => thumb.style.backgroundImage = `url('${reader.result}')`;
      reader.readAsDataURL(file);
    } else {
      thumb.style.backgroundImage = '';
    }
  }
  document.querySelectorAll('.tabslinks').forEach(el => {
    const capitalizeFirstLetter = str =>
      str && str[0].toUpperCase() + str.slice(1).toLowerCase();

    el.addEventListener('click', () => {
      const tabName = capitalizeFirstLetter(el.id);
      switchTab(tabName);
    });
  });


  document.querySelectorAll(".copy-mail").forEach(el => {
      el.style.cursor = "pointer";
      el.addEventListener("click", async () => {
        const email = el.dataset.email || el.textContent.trim();
        try {
          await navigator.clipboard.writeText(email);
          console.log("Copied:", email);
        } catch (err) {
          console.error("Copy failed:", err);
        }
      });
    });
});
