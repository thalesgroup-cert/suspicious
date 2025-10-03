function openTabs(evt, tabName) {
  document.querySelectorAll(".tabcontent").forEach(tab => {
    tab.style.display = "none";
  });

  document.querySelectorAll(".tabslinks").forEach(link => {
    link.classList.remove("is-active");
  });

  const tab = document.getElementById(tabName);
  if (tab) tab.style.display = "block";

  const tabLink = document.getElementById(tabName.toUpperCase());
  if (tabLink) tabLink.classList.add("is-active");
}

$(document).ready(function () {
  openTabs(null, "Preferences");
  $("#Preferences").addClass("is-active");

  document.getElementById("saveBtn").addEventListener("click", savePreferences);
});

const savePreferences = async () => {
  const wantsAcknowledgement = document.getElementById("ack").checked;
  const wantsResults = document.getElementById("res").checked;

  try {
    const response = await fetch("../update-preferences/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        wants_acknowledgement: wantsAcknowledgement,
        wants_results: wantsResults,
      }),
    });

    const result = await response.json();

    if (result.success) {
      console.log("Preferences updated successfully");
    } else {
      console.error("Error updating preferences:", result.message);
    }
  } catch (error) {
    console.error("Error updating preferences:", error);
  }
};



