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
  openTabs(null, "Domains");
  $("#Domains").addClass("is-active");
  $("label").hide();

  ["id_domain", "id_Bdomain", "id_campaign_domain", "id_file", "id_filetype"].forEach(id => {
    $("#" + id).addClass("input");
  });

  $("#id_domain").attr("placeholder", "Enter a valid Domain...");
  $("#id_Bdomain").attr("placeholder", "Enter a valid Domain...");
  $("#id_campaign_domain").attr("placeholder", "Enter a valid Campaign Domain...");
  $("#id_file").attr("placeholder", "Enter a valid File Hash...");
  $("#id_filetype").attr("placeholder", "Enter a valid Filetype...");

  $("#copy-btn").click(() => {
    const copyText = $("#mail").val();
    navigator.clipboard.writeText(copyText);
  });
});


function change() {
  // Centralise l'affichage des messages d'absence de données si besoin via showFeedback (optionnel)
  // Sinon, uniquement gestion des affichages
  const map = [
    { noElemId: "noBDomains", elemsClass: "allBDomains" },
    { noElemId: "noDomains", elemsClass: "allDomains" },
    { noElemId: "noCampaignDomains", elemsClass: "allCampaignDomains" },
    { noElemId: "noFiles", elemsClass: "allFiles" },
    { noElemId: "noFiletypes", elemsClass: "allFiletypes" }
  ];

  map.forEach(({ noElemId, elemsClass }) => {
    const noElem = document.getElementById(noElemId);
    const elems = document.getElementsByClassName(elemsClass);
    if (noElem) {
      noElem.style.display = (elems.length === 0) ? "block" : "none";
    }
  });
}
