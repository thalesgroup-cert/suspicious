function showFeedback(input, message, type) {
  const feedback = input.nextElementSibling;
  feedback.textContent = message;
  feedback.classList.add(type, "button");
  setTimeout(() => {
    feedback.textContent = input.id.includes("file")
      ? "Add from file"
      : "Add domain(s)";
    feedback.classList.remove(type, "button");
    if (input.type === "file") input.value = "";
  }, 3000);
}

function createBDiv(id, type) {
  const div = document.createElement("div");
  div.classList.add(`${type}BList`);
  div.id = `div-B${id}`;

  const p = document.createElement("p");
  p.id = id;

  const icon = document.createElement("i");
  switch (type) {
    case "domain":
      p.classList.add("allBDomains");
      icon.classList.add("fas", "fa-globe");
      break;
    case "file":
    case "filetype":
      p.classList.add(type === "file" ? "allFiles" : "allFiletypes");
      icon.classList.add("fas", "fa-file");
      break;
  }

  p.append(icon, ` ${id}`);
  div.appendChild(p);

  const buttonDiv = document.createElement("div");
  buttonDiv.classList.add(type);
  buttonDiv.id = `buttonDiv-B${id}`;

  const button = document.createElement("button");
  button.classList.add("button", "is-danger", "ddB");
  button.id = `button_B${id}`;
  button.type = "submit";
  button.textContent = "Remove";

  const removeFn = {
    domain: removeBDomain,
    file: removeFile,
    filetype: removeFiletype,
  }[type];

  if (removeFn) button.addEventListener("click", () => removeFn(id));

  buttonDiv.appendChild(button);
  div.appendChild(buttonDiv);
  return div;
}

function addBDomains() {
  const input = document.getElementById("file-Bdomain");
  const file = input.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append("file", file);

  fetch("../add-Bdomain-file/", { method: "POST", body: formData })
    .then((res) => res.json())
    .then((result) => {
      if (result.success) {
        const domains = result.domains || [];
        const message = domains.length
          ? `${result.domain_added_num} domains added !`
          : "No good Domains in file.";
        showFeedback(
          input,
          message,
          domains.length ? "is-success" : "is-danger"
        );

        domains.forEach((domain) => {
          if (!domain.trim()) return;
          const div = createDiv(domain, "domain");
          document.getElementById("list").appendChild(div);
          change();
        });
      } else {
        showFeedback(input, result.message, "is-danger");
      }
    });
}

function addBDomain() {
  const input = document.getElementById("id_Bdomain");
  const domains = input.value.split(/[ ,;]/).filter(Boolean);
  const existing = Array.from(document.querySelectorAll(".allBDomains")).map(
    (el) => el.innerHTML.replace('<i class="fas fa-globe"></i> ', "")
  );
  input.value = "";

  domains.forEach((domain) => {
    if (!domain) {
      showFeedback(input, "Please enter a domain", "is-danger");
      return;
    }

    if (existing.includes(domain)) {
      showFeedback(input, "Domain already listed", "is-danger");
      return;
    }

    fetch(`../add-Bdomain/${domain}`)
      .then((res) => res.json())
      .then((result) => {
        if (result.success) {
          showFeedback(input, `${domains.length} domains added!`, "is-success");
          const div = createBDiv(result.domain, "domain");
          document.getElementById("Blist").appendChild(div);
          change();
        } else {
          showFeedback(input, result.message, "is-danger");
        }
      });
  });
}

function removeBDomain(domain) {
  fetch(`../remove-Bdomain/${domain}`)
    .then((res) => res.json())
    .then((result) => {
      if (result.success) {
        document.getElementById(`buttonDiv-B${domain}`)?.remove();
        document.getElementById(`div-B${domain}`)?.remove();
        change();
      }
    });
}
