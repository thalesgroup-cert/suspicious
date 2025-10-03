function showFeedback(
  input,
  message,
  type = "is-success",
  resetText = "",
  isFile = false
) {
  const feedback = input.nextElementSibling;
  feedback.textContent = message;
  feedback.classList.add(type, "button");

  setTimeout(() => {
    feedback.textContent = resetText;
    feedback.classList.remove(type, "button");
    if (isFile) input.value = "";
  }, 3000);
}

async function addCampaignDomains() {
  const fileInput = document.getElementById("file-campaign-domain");
  if (fileInput.files.length === 0) return;

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  try {
    const response = await fetch("../add-campaign-domain-file/", {
      method: "POST",
      body: formData,
    });
    const result = await response.json();

    const feedbackText = result.success
      ? `${result.domain_added_num} campaign domains added!`
      : result.message;
    const feedbackType = result.success ? "is-success" : "is-danger";

    showFeedback(fileInput, feedbackText, feedbackType, "Add from file", true);

    if (result.success) {
      const list = document.getElementById("list-campaign-domain");
      result.domains.forEach((domain) => {
        const div = createCampaignDiv(domain, "campaign-domain");
        list.appendChild(div);
      });
      change();
    }
  } catch (err) {
    showFeedback(
      fileInput,
      "Error uploading file",
      "is-danger",
      "Add from file",
      true
    );
  }
}

async function addCampaignDomain() {
  const input = document.getElementById("id_campaign_domain");
  const raw = input.value.trim();
  input.value = "";

  if (!raw) {
    showFeedback(
      input,
      "Please enter a campaign domain",
      "is-danger",
      "Add campaign domain(s)"
    );
    return;
  }

  const domains = raw.split(/[ ,;]/).filter(Boolean);
  const existing = new Set(
    [...document.querySelectorAll(".allCampaignDomains")].map((p) =>
      p.textContent.trim().replace(/^[^ ]+ /, "")
    )
  );

  for (const domain of domains) {
    if (existing.has(domain)) {
      showFeedback(
        input,
        "Campaign domain already listed",
        "is-danger",
        "Add campaign domain(s)"
      );
      continue;
    }

    try {
      const response = await fetch(
        `../add-campaign-domain/${encodeURIComponent(domain)}`
      );
      const result = await response.json();

      const feedbackText = result.success
        ? `${domains.length} campaign domains added!`
        : result.message;
      const feedbackType = result.success ? "is-success" : "is-danger";

      showFeedback(input, feedbackText, feedbackType, "Add campaign domain(s)");

      if (result.success) {
        const list = document.getElementById("list-campaign-domain");
        const div = createCampaignDiv(result.domain, "campaign-domain");
        list.appendChild(div);
        change();
      }
    } catch (err) {
      showFeedback(
        input,
        "Network error",
        "is-danger",
        "Add campaign domain(s)"
      );
    }
  }
}

function createCampaignDiv(id, type) {
  const div = document.createElement("div");
  div.classList.add("campaignDomainList");
  div.id = `div-${id}`;

  const p = document.createElement("p");
  p.classList.add("allCampaignDomains");
  p.id = id;

  const icon = document.createElement("i");
  icon.classList.add("fas", "fa-globe");

  p.appendChild(icon);
  p.appendChild(document.createTextNode(` ${id}`));
  div.appendChild(p);
  const buttonDiv = document.createElement('div');
  buttonDiv.classList.add("domain");
  buttonDiv.id = 'buttonDiv-' + id;

  const button = document.createElement("button");
  button.classList.add("button", "is-danger", "ddB");
  button.id = `button_${id}`;
  button.type = "button";
  button.textContent = "Remove";
  button.addEventListener("click", () => removeCampaignDomain(id));
  buttonDiv.appendChild(button);
  div.appendChild(buttonDiv);

  return div;
}

async function removeCampaignDomain(domain) {
  try {
    const response = await fetch(
      `../remove-campaign-domain/${encodeURIComponent(domain)}`
    );
    const result = await response.json();

    if (result.success) {
      const div = document.getElementById(`div-${domain}`);
      if (div) div.remove();
      change();
    }
  } catch (err) {
    console.error(`Failed to remove campaign domain: ${domain}`);
  }
}
