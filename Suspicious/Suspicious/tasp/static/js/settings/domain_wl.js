function showFeedback(input, message, type) {
  const feedback = input.nextElementSibling;
  feedback.textContent = message;
  feedback.classList.add(type, "button");
  setTimeout(() => {
    feedback.textContent =
      input.id === "file-domain" ? "Add from file" : "Add domain(s)";
    feedback.classList.remove(type, "button");
    if (input.type === "file") input.value = "";
  }, 3000);
}

function createDivdwl(id, type) {
  const div = document.createElement('div');
  div.classList.add(type+'List');
  div.id = 'div-' + id;
  const p = document.createElement('p');
  p.id = id;
  const icon = document.createElement('i');
  if (type === 'domain') {
    p.classList.add('allDomains');
    icon.classList.add('fas', 'fa-globe');
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
  if (type === 'domain') {
    button.addEventListener('click', function() {
      removeDomain(id);
    });
  }
  buttonDiv.appendChild(button);
  div.appendChild(buttonDiv);
  return div;
}

function addDomains() {
  const input = document.getElementById("file-domain");
  const file = input.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append("file", file);

  fetch("../add-domain-file/", {
    method: "POST",
    body: formData,
  })
    .then((res) => res.json())
    .then((result) => {
      if (result.success) {
        const domains = result.domains || [];
        const message =
          domains.length === 0
            ? "No good Domains in file."
            : `${result.domain_added_num} domains added !`;
        showFeedback(
          input,
          message,
          domains.length ? "is-success" : "is-danger"
        );

        domains.forEach((domain) => {
          if (!domain.trim()) return;
          const div = createDivdwl(domain, "domain");
          document.getElementById("list").appendChild(div);
          change();
        });
      } else {
        showFeedback(input, result.message, "is-danger");
      }
    });
}

function addDomain() {
  const input = document.getElementById("id_domain");
  const domains = input.value.split(/[ ,;]/).filter(Boolean);
  input.value = "";

  const existingDomains = Array.from(
    document.querySelectorAll(".allDomains")
  ).map((el) => el.innerHTML.replace('<i class="fas fa-globe"></i> ', ""));

  domains.forEach((domain) => {
    if (domain === "") {
      showFeedback(input, "Please enter a domain", "is-danger");
      return;
    }
    if (existingDomains.includes(domain)) {
      showFeedback(input, "Domain already listed", "is-danger");
      return;
    }

    fetch(`../add-domain/${domain}`)
      .then((res) => res.json())
      .then((result) => {
        if (result.success) {
          showFeedback(input, `${domains.length} domains added!`, "is-success");
          const div = createDivdwl(result.domain, "domain");
          document.getElementById("list").appendChild(div);
          change();
        } else {
          showFeedback(input, result.message, "is-danger");
        }
      });
  });
}

function removeDomain(domain) {
  fetch(`../remove-domain/${domain}`)
    .then((res) => res.json())
    .then((result) => {
      if (result.success) {
        document.getElementById(`buttonDiv-${domain}`)?.remove();
        document.getElementById(`div-${domain}`)?.remove();
        change();
      }
    });
}
