function showFeedback(input, message, className) {
  const feedback = input.nextElementSibling;
  feedback.textContent = message;
  feedback.classList.add(className, "button");
  setTimeout(() => {
    feedback.textContent = "Save";
    feedback.classList.remove(className, "button");
  }, 3000);
}

async function addCiso() {
  const input = document.getElementById("id_ciso");
  const cisos = input.value.split(/[ ,;]/).filter(Boolean);
  const existingCisos = Array.from(document.querySelectorAll(".allcisos")).map(
    (ciso) => ciso.innerHTML.replace('<i class="fas fa-globe"></i> ', "")
  );

  input.value = "";

  for (const ciso of cisos) {
    if (!existingCisos.includes(ciso) && ciso !== "") {
      try {
        const response = await fetch(`../add-ciso/${encodeURIComponent(ciso)}`);
        const result = await response.json();

        const feedback = input.nextElementSibling;
        if (result.success) {
          feedback.textContent = "New cisos added!";
          feedback.classList.add("is-success", "button");

          const div = createDiv(result.ciso, "ciso");
          document.getElementById("list-ciso").appendChild(div);
          change();
        } else {
          feedback.textContent = result.message;
          feedback.classList.add("is-danger", "button");
        }

        setTimeout(() => {
          feedback.textContent = "Add ciso(s)";
          feedback.classList.remove("is-success", "is-danger", "button");
        }, 3000);
      } catch (error) {
        console.error("Error adding ciso:", error);
      }
    } else if (ciso === "") {
      showFeedback(input, "Please enter a ciso", "is-danger");
    } else {
      showFeedback(input, "ciso already listed", "is-danger");
    }
  }
}

async function addCisos() {
  const fileInput = document.getElementById("file-ciso");
  if (fileInput.files.length === 0) return;

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  try {
    const response = await fetch("../add-ciso-file/", {
      method: "POST",
      body: formData,
    });
    const result = await response.json();
    const feedback = fileInput.nextElementSibling;

    if (result.success) {
      const cisos = result.cisos.filter((c) => c.trim() !== "");

      feedback.textContent =
        cisos.length === 0
          ? "No good cisos in file."
          : `${result.ciso_added_num} cisos added!`;
      feedback.classList.toggle("is-danger", cisos.length === 0);
      feedback.classList.toggle("is-success", cisos.length > 0);

      cisos.forEach((ciso) => {
        const div = createDiv(ciso, "ciso");
        document.getElementById("list-ciso").appendChild(div);
        change();
      });
    } else {
      feedback.textContent = result.message;
      feedback.classList.add("is-danger", "button");
    }

    setTimeout(() => {
      feedback.textContent = "Add from file";
      feedback.classList.remove("is-danger", "is-success", "button");
      fileInput.value = "";
    }, 3000);
  } catch (error) {
    console.error("Error adding cisos from file:", error);
  }
}

async function removeCiso(ciso) {
  try {
    const response = await fetch(`../remove-ciso/${encodeURIComponent(ciso)}`);
    const result = await response.json();

    if (result.success) {
      document.getElementById(`buttonDiv-${ciso}`)?.remove();
      document.getElementById(`div-${ciso}`)?.remove();
      change();
    }
  } catch (error) {
    console.error("Error removing ciso:", error);
  }
}
