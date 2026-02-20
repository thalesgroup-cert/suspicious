document.addEventListener("DOMContentLoaded", function () {
  let buttons = document.querySelectorAll(".chartButton");
  buttons.forEach(function (button) {
    button.addEventListener("click", function () {
      let caseId = this.getAttribute("data-case-id");
      let rawData = window["analyzers" + caseId];
      // hide the button
      this.style.display = "none";
      if (typeof generateChart === "function") {
        generateChart(caseId, rawData);
      } else {
        console.error("generateChart function is not defined.");
      }
    });
  });
});

function fixJsonFormat(encodedString) {
  // Define an object that contains the characters to replace and their replacements
  const replacements = {
    "&quot;": '"',
    "&#x27;": "'",
    "&nbsp;": " ",
    "&lt;": "<",
    "&gt;": ">",
    "&amp;": "&",
    '\\["': "[",
    '"]': "]",
    "/": ",",
    '", "': ",",
    "'": '"',
  };

  // Loop through the replacements object and replace each character with its replacement
  Object.entries(replacements).forEach(([char, replacement]) => {
    const regex = new RegExp(char, "g");
    try{
      encodedString = encodedString.replace(regex, replacement);
    }catch(err){
      err;
    }
  });
  // Return the fixed string
  return encodedString;
}

function generateChart(caseId, rawData) {
  if (rawData.length === 0) {
    let canvas = document.getElementById(`chartCanvas${caseId}`);
    let parent = canvas.parentElement;
    canvas.remove();
    let p = document.createElement("p");
    p.innerHTML = "No analyzers triggered for this attachment";
    parent.appendChild(p);
  } else {
    const canvasId = `chartCanvas${caseId}`;
    const cleanedData = fixJsonFormat(rawData);
    let parsedData = [];

    try {
      parsedData = rawData;
    } catch (err) {
      parsedData = cleanedData.map((data) => JSON.parse(data.replaceAll("/", ",").replaceAll("'", '"')));
    }

    const analyzerDataNames = parsedData.map((data) => data.data.replaceAll(",", "/"));
    const analyzerScores = parsedData.map((data) => data.score);
    const analyzerConfidences = parsedData.map((data) => data.confidence);
    const analyzerNames = parsedData.map((data) => data.analyzer_name);
    const backgroundColors = analyzerScores.map(getBackgroundColor);

    const datasets = createAnalyzerDatasets(analyzerNames, analyzerScores, analyzerConfidences, backgroundColors);

    const name = [analyzerDataNames.reduce((a, b) => (a.length < b.length ? a : b))];
    const data = {
      labels: name,
      datasets: datasets,
    };

    const options = {
      scales: {
        y: createScaleConfig("Analyzer Score"),
        confidence: createScaleConfig("Analyzer Confidence", "right"),
      },
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: "top",
        },
        title: {
          display: true,
          text: "Analyzers triggered with their scores and confidences",
        },
      },
    };

    const config = {
      type: "bar",
      data: data,
      options: options,
    };

    const chart = new Chart(canvasId, config);
  }
}

function getBackgroundColor(score) {
  if (score < 3) {
    return "#008000"; // Green
  } else if (score < 6) {
    return "#ffa500"; // Orange
  } else {
    return "#FF0000"; // Red
  }
}

function createAnalyzerDatasets(names, scores, confidences, backgroundColors) {
  return names.flatMap((name, i) => [
    {
      label: `${name} Score`,
      data: [scores[i]],
      backgroundColor: backgroundColors[i],
      borderColor: backgroundColors[i],
      borderWidth: 1,
      type: "bar",
    },
    {
      label: `${name} Confidence`,
      data: [confidences[i]],
      backgroundColor: "rgba(94,192,213,0.3)",
      borderColor: "rgba(94,192,213,0.3)",
      borderWidth: 1,
      type: "bar",
      yAxisID: "confidence",
    },
    // Add an empty dataset between each existing dataset
    {
      label: "",
      data: [],
      backgroundColor: "transparent",
      borderColor: "transparent",
      borderWidth: 0,
      type: "bar",
    },
  ]).slice(0, -1); // Remove the last empty dataset
}

function createScaleConfig(title, position = "left") {
  return {
    beginAtZero: true,
    max: 10,
    min: 0,
    position: position,
    title: {
      display: true,
      text: title,
    },
  };
}

function copy(id) {
  const copies = document.getElementsByClassName("usermail");
  const inputToCopy = copies[id - 1];
  const copyText = inputToCopy.getAttribute("value");

  navigator.clipboard.writeText(copyText);
}


const elements = document.getElementsByClassName("result");
const statust = document.getElementsByClassName("status");
const buttons = document.querySelectorAll("canvasbutton");

for (let i = 0; i < elements.length; i++) {
  let value = elements[i].innerHTML.toUpperCase();
  let color = null;

  switch (value) {
    case "FAILURE":
    color = "lightgrey";
    break;
    case "SUSPICIOUS":
      color = "darkorange";
      break;
    case "INCONCLUSIVE":
      color = "peru";
      break;
    case "SAFE":
      color = "green";
      break;
    case "SAFE-ALLOW_LISTED":
      color = "green";
      break;
    case "DANGEROUS":
      color = "red";
      break;
    default:
      break;
  }
  if (color) {
    elements[i].style.color = color;
    
    elements[i].style.fontWeight = "bold";
    
    elements[i].innerHTML = value;
    
  }
}

for (let j = 0; j < statust.length; j++) {
  let statvalue = statust[j].innerHTML.toUpperCase();
  let color = null;

  switch (statvalue) {
    case "ON GOING":
      color = "orange";
      break;
    case "DONE":
      color = "green";
      break
    case "CHALLENGED":
      color = "turquoise";
      
      break;
    case "TO DO":
      color = "red";
      break;
    default:
      break;
  }

  if (color) {
    
    statust[j].style.color = color;
    
    statust[j].style.fontWeight = "bold";
  }
}



$(document).ready(function () {
  const statusList = document.querySelectorAll(".status");
  const caseIdList = document.querySelectorAll(".caseid");
  const testList = document.querySelectorAll(".tests");
  const resultList = document.querySelectorAll(".result");
  const challengeButtons = document.querySelectorAll(".challengebtn");
  challengeButtons.forEach((challengeButton) => {
    challengeButton.addEventListener("click", async () => {
      const hidden = challengeButton.value;
      const caseId = hidden;

      // hide the button
      challengeButton.style.display = "none";

      const challenge = confirm("Are you sure you want to challenge the results?");
      if (challenge) {
        try {
          const response = await fetch(`../challenge/${caseId}`);
          const result = await response.json();

          if (result.success) {
            alert("Challenge sent");
            // replace the button with a message
            const parentDiv = challengeButton.parentElement;
            parentDiv.innerHTML = `
              <p>Not Challengeable</p>
            `;
          }
        } catch (error) {
          console.error(`Error sending challenge: ${error}`);
        }
      }
    });
  });



  Array.from(buttons).forEach((button, i) => {
    button.disabled = statusList[i].innerHTML.toUpperCase() !== "DONE" ;
  });

  const updateStatus = async (i) => {
    var id = caseIdList[i].value;
    var test = id.split(",")

    fetch(`../compute/${test[0]}/${test[1]}`)
      .then(response => response.json())
      .then(result => {
        if (result.success) {
          testList[i].innerHTML = result.context.analysis_done;
          statusList[i].innerHTML = result.context.status;
          resultList[i].innerHTML = result.context.results;
          switch (result.context.status) {
            case "On Going":
              statusList[i].style.color = "orange";
              
              break;
            case "Done":
              statusList[i].style.color = "green";
              break;
            case "Challenged":
              statusList[i].style.color = "turquoise";


              break;
            case "To Do":
              statusList[i].style.color = "red";
              
              break;
            default:
              break;
          }
      
          const value = result.context.results.toUpperCase();
          switch (value) {
            case "FAILURE":
              resultList[i].style.color = "lightgrey";
              break;
            case "SUSPICIOUS":
              resultList[i].style.color = "orange";
              break;
            case "SAFE":
              resultList[i].style.color = "green";
              break;
            case "SAFE-ALLOW_LISTED":
              resultList[i].style.color = "green";
              break;
            case "INCONCLUSIVE":
              resultList[i].style.color = "lightsalmon";
              break;
            case "DANGEROUS":
              resultList[i].style.color = "red";
              
              break;
            default:
              break;
          }
      
          resultList[i].style.fontWeight = "bold";
          
          resultList[i].innerHTML = value;
          
        }
      }
    )

    
  };

  const updateAllStatus = async () => {
    for (let i = 0; i < statusList.length; i++) {
      if (statusList[i].innerHTML !== "Done" && statusList[i].innerHTML !== "Challenged") {
        await updateStatus(i);
      }
    }
    Array.from(buttons).forEach((button, i) => {
      button.disabled = statusList[i].innerHTML.toUpperCase() !== "DONE" && statusList[i].innerHTML.toUpperCase() !== "CHALLENGED";
    });
    setTimeout(updateAllStatus, 10000);
  };

  updateAllStatus();
});

function hide() {
  $("div.add-by").hide();
  $("div.filter-by").toggle("show");
}
function hide2() {
  $("div.filter-by").hide();
  $("div.add-by").toggle("show");
}

new TableManager(".tablemanager", {
  // tri initial : colonne 4 desc, colonne 2 desc, colonne 1 asc
  firstSort: [
    [4, "desc"],
    [2, "desc"],
    [1, "asc"],
  ],

  // colonnes désactivées pour le tri
  disable: ["last"],

  // colonnes contenant des dates + format à parser
  dateFormat: [[4, "MM-dd-yyyy"]],

  // activer le filtre par colonne (inputs sous les <th>)
  appendFilterby: true,

  // debug console
  debug: false,

  // vocabulaire custom
  labels: {
    filter: "Search",
    showRows: "Rows Per Page",
    noResult: "No result found"
  },

  // pagination activée
  pagination: true,

  // liste des choix pour "Rows Per Page"
  showRows: [10, 20, 50, 100],

  // désactiver le filtre sur colonne 4
  disableFilterBy: [4]
});



$("input.submit").click(function () {
  const row = document.getElementById("columnadd").value.toUpperCase();
  const idadd = document.getElementById("add").value
  switch (row) {
    case "ID":
      add_more_cases(id=idadd, ope="null");
      break;
    case "10":
      add_more_cases(id = "null", ope = "10");
      break;
    case "20":
      add_more_cases(id = "null", ope = "20");
      break;
    case "50":
      add_more_cases(id = "null", ope = "50");
      break;
    case "CUSTOM":
      add_more_cases(id = idadd, ope = "CUSTOM");
      break;
    case "ALL":
      add_more_cases(id = "null", ope = "ALL");
      break;
  }
  
});
$("#columnadd").change(function () {
  var row = $(this).val().toUpperCase();
  $("#add").hide();
  if (row == "ID" || row == "CUSTOM") {
    $("#add").show();
  }
});



function createTableRow(counter,caseId,split_user, user, mail, status, pub_date, analysis_done, file_type, hash_type, ip_type, url_type, results) {
  // Create the new table row element
  const tr = document.createElement('tr');
  let html = "";
  // Set the HTML content of the table row
  html = `
  <td data-label="Case #">
  <div>
    <button class="button js-modal-triggers has-background-link has-text-white caseid" onclick="openPop(${caseId})" value="${caseId}">${caseId}</button>
  </div>
  </td>
  <td class="user has-text-centered" data-label="User"><a onclick="copy(${counter})" id="" value="${user}" class="usermail"><p id="text" >${split_user}</p></a></td>
  <td class="status has-text-centered" data-label="Status">${status}</td>
  <td class="date has-text-centered" data-label="Date">${pub_date}</td>
  <td class="tests has-text-centered" data-label="Tests" class="test_done">${analysis_done}</td>
  `
  if (file_type){
    html += `
    <td class="type has-text-centered" data-label="Type">${file_type}</td>
    `
  }
  else if (hash_type){
    html += `
    <td class="type has-text-centered" data-label="Type">${hash_type}</td>
    `
  }
  else if (ip_type){
    html += `
    <td class="type has-text-centered" data-label="Type">${ip_type}</td>
    `
  }
  else if (url_type){
    html += `
    <td class="type has-text-centered" data-label="Type">${url_type}</td>
    `
  }
  else if (mail){
    html += `
    <td class="type has-text-centered" data-label="Type">Mail</td>
    `
  }
  html += `
  <td class="result has-text-centered" data-label="Result">${results}</td>
  `;
  tr.innerHTML = html;
  return tr;
}

function saveEdit(caseId) {
  const scoreInput = document.getElementById("scoreInput");
  const confidenceInput = document.getElementById("confidenceInput");
  const classificationInput = document.getElementById("classificationInput");

  const score = scoreInput.value;
  const confidence = confidenceInput.value;
  const classification = classificationInput.value;

  fetch(`../edit-global/${caseId}/${score}/${confidence}/${classification}`)
    .then(response => response.json())
    .then(({ success, score, confidence, classification }) => {
      if (success) {
        updateCaseInfo(score, confidence, classification);

        removeElement(scoreInput);
        removeElement(confidenceInput);
        removeElement(classificationInput);

        updateButton("edit", "Edit <i class='fas fa-edit'></i>", `edit(${caseId})`);
      }
    });
}

function updateCaseInfo(score, confidence, classification) {
  document.getElementById("scoreCase").textContent = `${score} / 10`;
  document.getElementById("confCase").textContent = `${confidence} %`;
  document.getElementById("resultCase").textContent = classification.toUpperCase();
}

function removeElement(element) {
  if (element) {
    element.remove();
  }
}

function updateButton(id, innerHTML, onclick) {
  const buttonEdit = document.getElementById(id);
  if (buttonEdit) {
    buttonEdit.innerHTML = innerHTML;
    buttonEdit.setAttribute("onclick", onclick);
  }
}

function edit(caseId) {
  const scoreCase = document.getElementById("scoreCase");
  const confCase = document.getElementById("confCase");
  const resultCase = document.getElementById("resultCase");

  const scoreValue = parseFloat(scoreCase.textContent.split(" ")[0]);
  const confidenceValue = parseFloat(confCase.textContent.split(" ")[0]);
  const classificationValue = resultCase.textContent.toUpperCase();

  const scoreInput = createInputElement("scoreInput", scoreValue, 0, 10, 0.1, "80px", true);
  const confidenceInput = createInputElement("confidenceInput", confidenceValue, 0, 100, 0.1, "80px", true);
  const classificationInput = createSelectElement("classificationInput", ["Safe", "Suspicious", "Failure", "Inconclusive", "Dangerous"], classificationValue);

  clearElementContent(scoreCase, confCase, resultCase);
  
  appendElements(scoreCase, scoreInput);
  appendElements(confCase, confidenceInput);
  appendElements(resultCase, classificationInput);

  updateButton("edit", "Save <i class='fas fa-save'></i>", `saveEdit(${caseId})`);
}

function clearElementContent(...elements) {
  elements.forEach(element => {
    if (element) {
      element.textContent = "";
    }
  });
}

function appendElements(parent, ...children) {
  children.forEach(child => {
    if (parent && child) {
      parent.appendChild(child);
    }
  });
}

function createInputElement(id, value, min, max, step, width, required) {
  const input = document.createElement("input");
  input.type = "number";
  input.id = id;
  input.value = value;
  input.min = min;
  input.max = max;
  input.step = step;
  input.classList.add("input");
  input.style.width = width;
  if (required) {
    input.required = true;
  }
  return input;
}

function createSelectElement(id, options, selectedValue) {
  const select = document.createElement("select");
  select.id = id;
  select.classList.add("input");
  select.style.width = "150px";
  select.required = true;

  options.forEach(optionValue => {
    const option = document.createElement("option");
    option.value = optionValue;
    option.textContent = optionValue;
    if (optionValue.toUpperCase() === selectedValue) {
      option.selected = true;
    }
    select.appendChild(option);
  });

  return select;
}

function openPop(id, user) {
  const divpop = document.getElementById("myPopup");

  fetchCaseData(id, user)
    .then(result => {
      if (result.success) {
        const pop = createPopUp(result.html);
        divpop.appendChild(pop);

        initializeModalBehavior(divpop, pop);

        applyStyling();
        
        addActionButtonListeners();

        addChallengeButtonListener();
      }
    })
    .catch(error => {
      console.error(`Error fetching case data: ${error}`);
    });
}

// Other helper functions can go here...

// Example helper functions:

async function fetchCaseData(id, user) {
  const response = await fetch(`../create-case-popup/${id}/${user}`);
  return response.json();
}

function initializeModalBehavior(divpop, pop) {
  const modals = document.querySelectorAll(".modal");
  const modalTriggers = document.querySelectorAll(".js-modal-triggers");
  const modalCloseElements = document.querySelectorAll(
    ".modal-close, .modal-card-head .delete, .modal-card-foot .button"
  );

  const openModal = ($el) => $el.classList.add("is-active");
  const closeModal = ($el) => $el.classList.remove("is-active");
  const closeAllModals = () => modals.forEach(closeModal);
  closeAllModals();

  openModal(divpop);

  modalCloseElements.forEach(($close) => {
    $close.addEventListener("click", () => {
      const $target = $close.closest(".modal");
      closeModal($target);
      divpop.removeChild(pop);
    });
  });

  document.addEventListener("keydown", (event) => {
    if (event.keyCode === 27) {
      // Escape key
      closeAllModals();
    }
  });
}

function applyStyling() {
  const cardStatus = document.getElementById("statusCase");
  const cardResult = document.getElementById("resultCase");

  // Apply styles based on status
  const statusColors = {
    "On Going": "orange",
    "Done": "green",
    "Challenged": "turquoise",
    "To Do": "red"
  };
  cardStatus.style.color = statusColors[cardStatus.innerHTML] || "";

  // Apply styles based on result
  const resultColors = {
    "FAILURE": "lightgrey",
    "SUSPICIOUS": "orange",
    "SAFE": "green",
    "SAFE-ALLOW_LISTED": "green",
    "INCONCLUSIVE": "lightsalmon",
    "DANGEROUS": "red"
  };
  const resultValue = cardResult.innerHTML.toUpperCase();
  cardResult.style.color = resultColors[resultValue] || "";
  cardResult.style.fontWeight = "bold";
  cardResult.innerHTML = resultValue;

  // Apply styles based on "Level" in title
  const elements = Array.from(document.querySelectorAll('h2'));
  const cardLevels = elements.filter(el => el.innerHTML.includes('Level'));
  
  cardLevels.forEach(cardLevel => {
    const cardLevelValue = cardLevel.nextElementSibling;
    const level = cardLevelValue.innerHTML.toUpperCase();
    cardLevelValue.innerHTML = level;

    const card = cardLevel.parentElement;
    const card_background = card.parentElement;

    switch (level) {
      case "MALICIOUS":
        card_background.style.backgroundColor = "red";
        break;
      case "SUSPICIOUS":
        card_background.style.backgroundColor = "orange";
        break;
      case "SAFE-ALLOW_LISTED":
      case "SAFE":
        card_background.style.backgroundColor = "green";
        break;
      case "INFO":
        card_background.style.backgroundColor = "grey";
        break;
      default:
        break;
    }
  });
}

function addActionButtonListeners() {
  // Add event listeners for action buttons (malicious, suspicious, safe)...

  $("button.malicious").click(function () {
    const id = $(this).attr("id").split("#")[1];
    const type = $(this).attr("id").split("#")[0];
    const caseId = this.getAttribute("data-case-id");
    setIocLevel(id, type, "malicious", this, caseId);
  });

  $("button.suspicious").click(function () {
    const id = $(this).attr("id").split("#")[1];
    const type = $(this).attr("id").split("#")[0];
    const caseId = this.getAttribute("data-case-id");
    setIocLevel(id, type, "suspicious", this, caseId);
  });

  $("button.safe").click(function () {
    const id = $(this).attr("id").split("#")[1];
    const type = $(this).attr("id").split("#")[0];
    const caseId = this.getAttribute("data-case-id");
    setIocLevel(id, type, "safe", this, caseId);
  });
}

function addChallengeButtonListener() {
  // Add event listener for the challenge button...

  const challengeButton = document.querySelector("#challenge");
  if (challengeButton) {
    challengeButton.addEventListener("click", async () => {
      const hidden = document.querySelector("#case_id").value;
      const [caseId, user, results] = hidden.split(",");

      // hide the button
      challengeButton.style.display = "none";

      const challenge = confirm("Are you sure you want to challenge the results?");
      if (challenge) {
        try {
          const response = await fetch(`../challenge/${caseId}`);
          const result = await response.json();

          if (result.success) {
            alert("Challenge sent");
            const divChall = document.getElementById("divChall");
            divChall.innerHTML = `
              <h4 class="title is-4 mt-2 ml-4 mb-1"><i class="fas fa-gear"></i>Result Challenged</h4>
              <p>Challenge sent</p>
              <p>Your Challenge has been sent. We will take a look and send another conclusion to you as soon as possible.</p>
            `;
          }
        } catch (error) {
          console.error(`Error sending challenge: ${error}`);
        }
      }
    });
  }
}

function parsePubDate(pub_date) {
  if (!pub_date) return null;

  // Format attendu : "DD/MM/YYYY HH:MM:SS"
  const [datePart, timePart] = pub_date.split(' ');
  if (!datePart || !timePart) return null;

  const [day, month, year] = datePart.split('/');
  if (!day || !month || !year) return null;

  // Construction ISO 8601 : YYYY-MM-DDTHH:MM:SS
  const isoString = `${year}-${month.padStart(2,'0')}-${day.padStart(2,'0')}T${timePart}`;
  const dateObj = new Date(isoString);
  return isNaN(dateObj.getTime()) ? null : dateObj;
}

function createPopUp(result) {
  const {
    case_id,
    file,
    file_info,
    file_hash,
    hash,
    hash_info,
    url,
    url_info,
    url_id,
    url_vt_id,
    mail,
    mail_body,
    mail_body_info,
    mail_header,
    mail_header_info,
    ip,
    ip_info,
    status,
    pub_date,
    analysis_done,
    case_score,
    file_name,
    file_type,
    hash_type,
    confidence,
    attachments,
    artifacts,
    results,
    challenge,
    case_file_analyzers,
    case_file_hash_analyzers,
    case_hash_analyzers,
    case_ip_analyzers,
    case_url_analyzers,
    case_mail_body_analyzers,
    case_mail_header_analyzers,
    case_mail_attachments_analyzers,
    case_mail_artifacts_analyzers,
    user,
  } = result;

  // Création du conteneur modal
  const modalBg = document.createElement('div');
  modalBg.classList.add('modal-background');
  modalBg.setAttribute('role', 'dialog');
  modalBg.setAttribute('aria-modal', 'true');
  modalBg.setAttribute('aria-labelledby', 'modal-title');

  const modalCard = document.createElement('div');
  modalCard.classList.add('modal-card');

  // Header
  const header = document.createElement('header');
  header.classList.add('modal-card-head');

  const title = document.createElement('h2');
  title.classList.add('modal-card-title');
  title.id = 'modal-title';
  title.textContent = `Submission Results Overview for Case n°${case_id}`;

  const closeButton = document.createElement('button');
  closeButton.classList.add('delete');
  closeButton.setAttribute('aria-label', 'Close');
  closeButton.title = 'Close';
  closeButton.setAttribute('data-dismiss', 'modal');

  header.append(title, closeButton);

  // Body section
  const section = document.createElement('section');
  section.classList.add('modal-card-body');

  const analysisDiv = document.createElement('div');
  analysisDiv.classList.add('analysis_result');

  // Title for analysis results
  const analysisTitle = document.createElement('h3');
  analysisTitle.classList.add('title', 'is-3');
  analysisTitle.textContent = 'Analysis Results';

  analysisDiv.appendChild(analysisTitle);

  // Challenge info
  const challengeInfo = document.createElement('p');
  challengeInfo.innerHTML = challenge
    ? `<i class="fas fa-exclamation-triangle"></i> This case has been challenged`
    : `<i class="fas fa-exclamation-triangle"></i> This case has not been challenged`;

  // Append renderCommonAnalysis result (assumed to return DOM nodes or HTML strings)
  // If these render functions return HTML strings, consider converting them to DOM nodes similarly or use innerHTML safely
  if (typeof renderCommonAnalysis === 'function') {
    const commonAnalysisHTML = renderCommonAnalysis(user, status, pub_date, analysis_done, case_score, results, confidence, challengeInfo.innerHTML);
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = commonAnalysisHTML;
    analysisDiv.appendChild(tempDiv);
  }

  // Conditional renderings (similarly handled)
  const renderFunctions = [
    { condition: file, fn: () => renderFileAnalysis(file_name, file_type, file_hash, file_info, case_id, case_file_analyzers, case_file_hash_analyzers) },
    { condition: hash, fn: () => renderHashAnalysis(hash, hash_type, hash_info, case_id, case_hash_analyzers) },
    { condition: url, fn: () => renderUrlAnalysis(url, url_info, case_id, url_id, url_vt_id, case_url_analyzers) },
    { condition: ip, fn: () => renderIpAnalysis(ip, ip_info, case_id, case_ip_analyzers) },
  ];

  renderFunctions.forEach(({ condition, fn }) => {
    if (condition && typeof fn === 'function') {
      const htmlStr = fn();
      const tempDiv = document.createElement('div');
      tempDiv.innerHTML = htmlStr;
      analysisDiv.appendChild(tempDiv);
    }
  });

  if (mail && mail_header && typeof renderMailHeaderAnalysis === 'function') {
    const htmlStr = renderMailHeaderAnalysis(mail_header, mail_header_info, case_id, case_mail_header_analyzers);
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = htmlStr;
    analysisDiv.appendChild(tempDiv);
  }

  if (mail && mail_body && typeof renderMailBodyAnalysis === 'function') {
    const htmlStr = renderMailBodyAnalysis(mail_body, mail_body_info, case_id, case_mail_body_analyzers);
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = htmlStr;
    analysisDiv.appendChild(tempDiv);
  }

  if (artifacts && typeof renderArtifactsAnalysis === 'function') {
    const htmlStr = renderArtifactsAnalysis(artifacts, case_id, case_mail_artifacts_analyzers);
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = htmlStr;
    analysisDiv.appendChild(tempDiv);
  }

  if (attachments && typeof renderAttachmentsAnalysis === 'function') {
    const htmlStr = renderAttachmentsAnalysis(attachments, case_id, case_mail_attachments_analyzers);
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = htmlStr;
    analysisDiv.appendChild(tempDiv);
  }

  // Date parsing et calcul différence
  const pubDateObj = parsePubDate(pub_date);
  if (pubDateObj) {
    const now = new Date();
    const diffMs = Math.abs(now - pubDateObj);
    const diffDays = Math.ceil(diffMs / (1000 * 3600 * 24));

    if (!challenge && diffDays < 7 && typeof renderChallengeSection === 'function') {
      const challengeHTML = renderChallengeSection(case_id, user, results);
      const tempDiv = document.createElement('div');
      tempDiv.innerHTML = challengeHTML;
      analysisDiv.appendChild(tempDiv);
    }
  }

  section.appendChild(analysisDiv);

  modalCard.append(header, section);
  modalBg.appendChild(modalCard);

  return modalBg;
}

function renderFileAnalysis(file_name, file_type, file_hash, file_info = [], case_id, case_file_analyzers = [], case_file_hash_analyzers = []) {
  if (!file_name) return document.createDocumentFragment();

  const fragment = document.createDocumentFragment();

  const card = document.createElement('div');
  card.className = "card pt-2 pb-4 mb-4";

  const title = document.createElement('h4');
  title.className = "title is-4 mt-2 ml-4 mb-1";
  title.innerHTML = `<i class="fas fa-paperclip"></i> File`;
  card.appendChild(title);

  const pName = document.createElement('p');
  pName.textContent = `File name: ${file_name}`;
  card.appendChild(pName);

  if (file_type) {
    const pType = document.createElement('p');
    pType.textContent = `File type: ${file_type}`;
    card.appendChild(pType);
  }

  if (file_hash) {
    const pHash = document.createElement('p');
    pHash.textContent = `File hash: ${file_hash}`;
    card.appendChild(pHash);
  }

  // Ajouter score/confiance
  const scoreConfContainer = document.createElement('div');
  scoreConfContainer.innerHTML = renderFileScoreConfidenceLevel(file_info, case_id);
  card.appendChild(scoreConfContainer);

  // Bouton pour détails analyzers
  const btnToggle = document.createElement('button');
  btnToggle.className = "button is-link";
  btnToggle.type = 'button';
  btnToggle.textContent = "More details ";
  const iconDown = document.createElement('i');
  iconDown.className = "fas fa-chevron-down";
  btnToggle.appendChild(iconDown);

  // Container analyzers (initialement caché)
  const analyzersContainer = document.createElement('div');
  analyzersContainer.className = "file_analyzers";
  analyzersContainer.style.display = "none";

  // Remplir analyzers
  const analyzersContent = renderFileAnalyzers(file_hash, file_name, case_file_analyzers, case_file_hash_analyzers);
  // renderFileAnalyzers renvoie du HTML, on convertit en DOM
  const tempDiv = document.createElement('div');
  tempDiv.innerHTML = analyzersContent;
  analyzersContainer.appendChild(tempDiv);

  // Toggle affichage analyzers
  btnToggle.addEventListener('click', () => {
    const isHidden = analyzersContainer.style.display === "none";
    analyzersContainer.style.display = isHidden ? "block" : "none";
    btnToggle.innerHTML = isHidden ? `Less details <i class="fas fa-chevron-up"></i>` : `More details <i class="fas fa-chevron-down"></i>`;
  });

  card.appendChild(btnToggle);
  card.appendChild(analyzersContainer);

  fragment.appendChild(card);
  return fragment;
}

// renderFileScoreConfidenceLevel retourne du HTML, on peut garder la fonction inchangée
// même si pour plus de robustesse on pourrait aussi la moderniser
function renderFileScoreConfidenceLevel(file_info = [], case_id) {
  // protection minimaliste
  const score = file_info[0] ?? 'N/A';
  const confidence = file_info[1] != null ? `${file_info[1]} %` : 'N/A';
  const level = file_info[2] ? file_info[2].toUpperCase() : 'N/A';

  return `
    <div class="container">
      <div class="columns is-centered is-multiline dash mt-5">
        ${renderFileCard("File Score", score, "fileScore")}
        ${renderFileCard("File Confidence", confidence, "fileConf")}
        ${renderFileCard("File Level", level, "fileLevel")}
      </div>
    </div>`;
}

function renderFileAnalyzers(file_hash, file_name, case_file_analyzers = [], case_file_hash_analyzers = []) {
  const analyzersFound = [...case_file_analyzers, ...case_file_hash_analyzers].filter(analyzer =>
    analyzer.artifact === file_hash || analyzer.artifact === file_name
  );

  if (analyzersFound.length === 0) {
    return `
      <div class="columns is-centered is-multiline">
        <div class="main column is-one-third">
          <div class="card">
            <div class="card-content">
              <div class="content">
                <p>No analyzers found</p>
              </div>
            </div>
          </div>
        </div>
      </div>`;
  }

  return `
    <div class="columns is-centered is-multiline">
      ${analyzersFound.map((analyzer, i) => {
        const { analyzer_name, status, score, confidence, level } = analyzer;
        return renderAnalyzerCard(analyzer_name, status, score, confidence, level, `analyzer-${i}`, file_hash, "file", 0);
      }).join('')}
    </div>`;
}


function renderAnalyzerCard(analyzer_name, status, score, confidence, level, id, object, type, url_vt_id) {
  if (analyzer_name !== "null" && analyzer_name === "VirusTotal_GetReport_3_1") {
    if(type=== "url"){
      return `
      <div class="main column is-one-third">
        <div class="card">
          <div class="card-content">
            <div class="content">
              <h2 class="title is-4">${analyzer_name}</h2>
              <p>Status: ${status}</p>
              <p>Score: ${score}</p>
              <p>Confidence: ${confidence}</p>
              <p>Level: ${level}</p>
              <p>Link: <a href="https://www.virustotal.com/gui/${type}/${url_vt_id}" target="_blank">VirusTotal</a></p>
            </div>
          </div>
        </div>
      </div>`;
    }
    return `
    <div class="main column is-one-third">
      <div class="card">
        <div class="card-content">
          <div class="content">
            <h2 class="title is-4">${analyzer_name}</h2>
            <p>Status: ${status}</p>
            <p>Score: ${score}</p>
            <p>Confidence: ${confidence}</p>
            <p>Level: ${level}</p>
            <p>Link: <a href="https://www.virustotal.com/gui/${type}/${object}" target="_blank">VirusTotal</a></p>
          </div>
        </div>
      </div>
    </div>`;
  } else {
    return `
        <div class="main column is-one-third">
          <div class="card">
            <div class="card-content">
              <div class="content">
                <h2 class="title is-4">${analyzer_name}</h2>
                <p>Status: ${status}</p>
                <p>Score: ${score}</p>
                <p>Confidence: ${confidence}</p>
                <p>Level: ${level}</p>
              </div>
            </div>
          </div>
        </div>`;
  }
}


function renderFileCard(title, content, id) {
  return `
    <div class="main column is-narrow">
      <div class="card">
        <div class="card-content">
          <div class="content">
            <h2 class="title is-4">${title}</h2>
            <p id="${id}" class="subtitle is-6">${content}</p>
          </div>
        </div>
      </div>
    </div>`;
}



function renderHashAnalysis(hash, hash_type, hash_info, case_id,case_hash_analyzers) {
  let html = "";
  if (hash) {
    html += `
      <div class="card pt-2 pb-4 mb-4">
        <h4 class="title is-4 mt-2 ml-4 mb-1"><i class="fas fa-fingerprint"></i> Hash</h4>
        <p>Hash: ${hash}</p>`;
    if (hash_type) {
      html += `
        <p>Hash type: ${hash_type}</p>`;
    }
    html += renderHashScoreConfidenceLevel(hash_info, case_id);
    // Add a button to hide the hash analyzers
    html += `
      <div class="button">
        <button class="button is-link" onclick="details_hash('${hash}');" id="hash_analyzers_button#${hash}">More details <i class='fas fa-chevron-down'></i></button>
      </div>
      <div class="hash_analyzers" id="hash_analyzers#${hash}" style="display: none;">`;
    

    html += renderHashAnalyzers(hash, case_hash_analyzers);  
    html += `</div>`;
  }
  return html;
}

function details_hash(hash) {
  let analyzers = document.getElementById("hash_analyzers#" + hash);
  let analyzers_button = document.getElementById("hash_analyzers_button#" + hash);
  if (!analyzers || !analyzers_button) {
    console.error(`No analyzers or button found for hash: ${hash}`);
    return;
  }
  if (analyzers.style.display == "none") {
    analyzers.style.display = "block";
    analyzers_button.innerHTML = "Less details <i class='fas fa-chevron-up'></i>";
  } else {
    analyzers.style.display = "none";
    analyzers_button.innerHTML = "More details <i class='fas fa-chevron-down'></i>";
  }
}

function renderHashScoreConfidenceLevel(hash_info, case_id) {
  return `
    <div class="container">
      <div class="columns is-centered is-multiline dash mt-5">
        ${renderHashCard("Hash Score", hash_info[0], "hashScore")}
        ${renderHashCard("Hash Confidence", `${hash_info[1]} %`, "hashConf")}
        ${renderHashCard("Hash Level", hash_info[2].toUpperCase(), "hashLevel")}
      </div>
    </div>`;
}

function renderHashAnalyzers(hash, case_hash_analyzers) {
  let analyzerHtml = '';
  let foundAnalyzers = false;

  case_hash_analyzers.forEach(analyzer => {

    // Match analyzer based on hash value
    if (analyzer.artifact === hash) {
      foundAnalyzers = true;
      analyzerHtml += `
        <div class="main column is-one-third">
          <div class="card">
            <div class="card-content">
              <div class="content">
                <h2 class="title is-4">${analyzer.analyzer_name}</h2>
                <p>Status: ${analyzer.status}</p>
                <p>Score: ${analyzer.score}</p>
                <p>Confidence: ${analyzer.confidence}</p>
                <p>Level: ${analyzer.level}</p>
              </div>
            </div>
          </div>
        </div>`;
    }
  });

  if (!foundAnalyzers) {
    analyzerHtml = `
      <div class="columns is-centered is-multiline">
        <div class="main column is-one-third">
          <div class="card">
            <div class="card-content">
              <div class="content">
                <p>No analyzers found</p>
              </div>
            </div>
          </div>
        </div>
      </div>`;
  }

  return analyzerHtml;
}


function renderHashCard(title, content, id) {
  return `  
    <div class="main column is-narrow">
      <div class="card">
        <div class="card-content">
          <div class="content">
            <h2 class="title is-4">${title}</h2>
            <p id="${id}" class="subtitle is-6">${content}</p>
          </div>
        </div>
      </div>
    </div>`;
}




function renderUrlAnalysis(url, url_info, case_id, url_id, url_vt_id, case_url_analyzers) {
  let html = "";
  if (url) {
    html += `
      <div class="card pt-2 pb-4 mb-4">
        <h4 class="title is-4 mt-2 ml-4 mb-1"><i class="fas fa-link"></i> URL</h4>
        <p>${url}</p>`;
    html += renderUrlScoreConfidenceLevel(url_info, case_id);

    // Add a button to toggle URL analyzers
    html += `
      <div class="button">
        <button class="button is-link" onclick="details_url('${url}');" id="url_analyzers_button#${url}">More details <i class='fas fa-chevron-down'></i></button>
      </div>
      <div class="url_analyzers" id="url_analyzers#${url}" style="display: none;">`;
    
    html += renderUrlAnalyzers(url, case_url_analyzers, url_vt_id);
    html += `</div>`;
  }
  return html;
}

function details_url(url) {
  let analyzers = document.getElementById("url_analyzers#" + url);
  let analyzers_button = document.getElementById("url_analyzers_button#" + url);

  if (analyzers.style.display == "none") {
    analyzers.style.display = "block";
    analyzers_button.innerHTML = "Less details <i class='fas fa-chevron-up'></i>";
  } else {
    analyzers.style.display = "none";
    analyzers_button.innerHTML = "More details <i class='fas fa-chevron-down'></i>";
  }
}

function renderUrlScoreConfidenceLevel(url_info, case_id) {
  return `  
    <div class="container">
      <div class="columns is-centered is-multiline dash mt-5">
        ${renderUrlCard("URL Score", url_info[0], "urlScore")}
        ${renderUrlCard("URL Confidence", `${url_info[1]} %`, "urlConf")}
        ${renderUrlCard("URL Level", url_info[2].toUpperCase(), "urlLevel")}
      </div>
    </div>`;
}

function renderUrlAnalyzers(url, case_url_analyzers, url_vt_id) {
  let type = "url";
  let analyzersFound = [];

  if (url !== "" && url.length > 0) {
    case_url_analyzers.forEach((analyzer) => {
      if (analyzer.artifact === url) {
        analyzersFound.push(analyzer);
      }
    });

    if (analyzersFound.length > 0) {
      return `
        <div class="columns is-centered is-multiline">
          ${analyzersFound.map((analyzer, index) => `
            ${renderAnalyzerCard(analyzer.analyzer_name, analyzer.status, analyzer.score, analyzer.confidence, analyzer.level, `analyzer-${index}`, url, type, url_vt_id)}
          `).join('')}
        </div>`;
    }
  }
  return `
  <div class="columns is-centered is-multiline">
    <div class="main column is-one-third">
      <div class="card">
        <div class="card-content">
          <div class="content">
            <p>No analyzers found</p>
          </div>
        </div>
      </div>
    </div>
  </div>
  `;
}

function renderUrlCard(title, content, id) {
  return `  
    <div class="main column is-narrow">
      <div class="card">
        <div class="card-content">
          <div class="content">
            <h2 class="title is-4">${title}</h2>
            <p id="${id}" class="subtitle is-6">${content}</p>  
          </div>  
        </div>
      </div>
    </div>`;
}

function renderIpAnalysis(ip, ip_info, case_id, case_ip_analyzers) {
  let html = "";
  if (ip) {
    html += `
      <div class="card pt-2 pb-4 mb-4">
        <h4 class="title is-4 mt-2 ml-4 mb-1"><i class="fas fa-link"></i> IP</h4>
        <p>IP: ${ip}</p>`;
    html += renderIpScoreConfidenceLevel(ip_info, case_id);

    // Add a button to toggle IP analyzers
    html += `
      <div class="button">
        <button class="button is-link" onclick="details_ip('${ip}');" id="ip_analyzers_button#${ip}">More details <i class='fas fa-chevron-down'></i></button>
      </div>
      <div class="ip_analyzers" id="ip_analyzers#${ip}" style="display: none;">`;
    
    html += renderIpAnalyzers(ip, case_ip_analyzers);
    html += `</div>`;
  }
  return html;
}

function details_ip(ip) {
  let analyzers = document.getElementById("ip_analyzers#" + ip);
  let analyzers_button = document.getElementById("ip_analyzers_button#" + ip);

  if (analyzers.style.display == "none") {
    analyzers.style.display = "block";
    analyzers_button.innerHTML = "Less details <i class='fas fa-chevron-up'></i>";
  } else {
    analyzers.style.display = "none";
    analyzers_button.innerHTML = "More details <i class='fas fa-chevron-down'></i>";
  }
}

function renderIpScoreConfidenceLevel(ip_info, case_id) {
  return `
    <div class="container">
      <div class="columns is-centered is-multiline dash mt-5">
        ${renderIpCard("IP Score", ip_info[0], "ipScore")}
        ${renderIpCard("IP Confidence", `${ip_info[1]} %`, "ipConf")}
        ${renderIpCard("IP Level", ip_info[2].toUpperCase(), "ipLevel")}
      </div>
    </div>`;
}

function renderIpAnalyzers(ip, case_ip_analyzers) {
  let type = "ip-address";
  let analyzersFound = [];

  if (ip !== "" && ip.length > 0) {
    case_ip_analyzers.forEach((analyzer) => {
      if (analyzer.artifact === ip) {
        analyzersFound.push(analyzer);
      }
    });

    if (analyzersFound.length > 0) {
      return `
        <div class="columns is-centered is-multiline">
          ${analyzersFound.map((analyzer, index) => `
            ${renderAnalyzerCard(analyzer.analyzer_name, analyzer.status, analyzer.score, analyzer.confidence, analyzer.level, `analyzer-${index}`, ip, type, 0)}
          `).join('')}
        </div>`;
    }
  }
  return `
  <div class="columns is-centered is-multiline">
    <div class="main column is-one-third">
      <div class="card">
        <div class="card-content">
          <div class="content">
            <p>No analyzers found</p>
          </div>
        </div>
      </div>
    </div>
  </div>
  `;
}

function renderIpCard(title, content, id) {
  return `
    <div class="main column is-narrow">
      <div class="card">
        <div class="card-content">
          <div class="content">
            <h2 class="title is-4">${title}</h2>
            <p id="${id}" class="subtitle is-6">${content}</p>
          </div>
        </div>
      </div>
    </div>`;
}

function renderCommonAnalysis(user, status, pub_date, analysis_done, case_score, results, confidence, challenge) {
  return `
      ${renderCard("fas fa-user", "User", user, "user")}
      ${renderCard("fas fa-info-circle", "Status", status, "statusCase")}
      ${renderCard("fas fa-calendar-alt", "Date", pub_date, "date")}
      ${renderCard("fas fa-check", "Tests Done", analysis_done, "testCase")}
      ${renderCard("fas fa-star", "Case Score", `${case_score} / 10`, "scoreCase")}
      ${renderCard("fas fa-flag", "Classification", results, "resultCase")}
      ${renderCard("fas fa-percent", "Confidence", `${confidence} %`, "confCase")}
      ${renderCard("fas fa-gear", "Challenged", challenge, "divChall")}`;
}

function renderMailHeaderAnalysis(mailHeader, mailHeaderInfo, case_id,case_mail_header_analyzers) {
  let html = "";
  if (mailHeader) {
    html += `
      <div class="card pt-2 pb-4 mb-4">
        <h4 class="title is-4 mt-2 ml-4 mb-1"><i class="fas fa-envelope"></i> Mail Header</h4>
        <p>Mail Header Hash: ${mailHeader}</p>`;

    html += renderMailHeaderScoreConfidenceLevel(mailHeaderInfo, case_id);

    html += `
      <div class="button">
        <button class="button is-link" onclick="details_header();" id="mail_header_analyzers_button">More details <i class='fas fa-chevron-down'></i></button>
      </div>
      <div class="mail_header_analyzers" id="mail_header_analyzers" style="display: none;">`;
    
    
    html += renderMailHeaderAnalyzers(mailHeader,case_mail_header_analyzers);
    html += `</div>`;
  }
  return html;
}

function details_header() {
  let analyzers = document.getElementById("mail_header_analyzers");
  let analyzers_button = document.getElementById("mail_header_analyzers_button");
  if (analyzers.style.display == "none") {
    analyzers.style.display = "block";
    analyzers_button.innerHTML = "Less details <i class='fas fa-chevron-up'></i>";
  } else {
    analyzers.style.display = "none";
    analyzers_button.innerHTML = "More details <i class='fas fa-chevron-down'></i>";
  }
}

function renderMailHeaderScoreConfidenceLevel(mailHeaderInfo, case_id) {
  return `
    <div class="container">
      <div class="columns is-centered is-multiline dash mt-5">
        ${renderMailHeaderCard("Header Score", mailHeaderInfo[0], "headerScore")}
        ${renderMailHeaderCard("Header Confidence", `${mailHeaderInfo[1]} %`, "headerConf")}
        ${renderMailHeaderCard("Header Level", mailHeaderInfo[2].toUpperCase(), "headerLevel")}
      </div>
    </div>`;
}

function renderMailHeaderAnalyzers(mailHeader,case_mail_header_analyzers) {
  let type = "mail-header";
  return `
    <div class="columns is-centered is-multiline">
      ${case_mail_header_analyzers.map((analyzer, index) => `
          ${renderAnalyzerCard(analyzer.analyzer_name, analyzer.status, analyzer.score, analyzer.confidence, analyzer.level, `analyzer-${index}`, mailHeader, type, 0)}
      `).join('')}
    </div>`;
}

function renderMailHeaderCard(title, content, id) {
  return `
    <div class="main column is-narrow">
      <div class="card">
        <div class="card-content">
          <div class="content">
            <h2 class="title is-4">${title}</h2>
            <p id="${id}" class="subtitle is-6">${content}</p>
          </div>
        </div>
      </div>
    </div>`;
}

function renderMailBodyAnalysis(mailBody, mailBodyInfo, case_id,case_mail_body_analyzers) {
  let html = "";
  if (mailBody) {
    html += `
      <div class="card pt-2 pb-4 mb-4">
        <h4 class="title is-4 mt-2 ml-4 mb-1"><i class="fas fa-envelope"></i> Mail Body</h4>
        <p>Mail Body Hash: ${mailBody}</p>`;

    html += renderMailBodyScoreConfidenceLevel(mailBodyInfo, case_id);
    html += `
      <div class="button">
        <button class="button is-link" onclick="details_body();" id="mail_body_analyzers_button">More details <i class='fas fa-chevron-down'></i></button>
      </div>
      <div class="mail_body_analyzers" id="mail_body_analyzers" style="display: none;">`;
    
    
    html += renderMailBodyAnalyzers(mailBody,case_mail_body_analyzers);
    html += `</div>`;
  }
  return html;
}

function details_body() {
  let analyzers = document.getElementById("mail_body_analyzers");
  let analyzers_button = document.getElementById("mail_body_analyzers_button");
  if (analyzers.style.display == "none") {
    analyzers.style.display = "block";
    analyzers_button.innerHTML = "Less details <i class='fas fa-chevron-up'></i>";
  } else {
    analyzers.style.display = "none";
    analyzers_button.innerHTML = "More details <i class='fas fa-chevron-down'></i>";
  }
}

function renderMailBodyScoreConfidenceLevel(mailBodyInfo, case_id) {
  return `
    <div class="container">
      <div class="columns is-centered is-multiline dash mt-5">
        ${renderMailBodyCard("Body Score", mailBodyInfo[0], "bodyScore")}
        ${renderMailBodyCard("Body Confidence", `${mailBodyInfo[1]} %`, "bodyConf")}
        ${renderMailBodyCard("Body Level", mailBodyInfo[2].toUpperCase(), "bodyLevel")}
      </div>
    </div>`;
}

function renderMailBodyAnalyzers(mailBody,case_mail_body_analyzers) {
  let type = "mail-body";
  return `
    <div class="columns is-centered is-multiline">
      ${case_mail_body_analyzers.map((analyzer, index) => `
          ${renderAnalyzerCard(analyzer.analyzer_name, analyzer.status, analyzer.score, analyzer.confidence, analyzer.level, `analyzer-${index}`, mailBody, type, 0)}
      `).join('')}
    </div>`;
}

function renderMailBodyCard(title, content, id) {
  return `
    <div class="main column is-narrow">
      <div class="card">
        <div class="card-content">
          <div class="content">
            <h2 class="title is-4">${title}</h2>
            <p id="${id}" class="subtitle is-6">${content}</p>
          </div>
        </div>
      </div>
    </div>`;
}

function renderArtifactsAnalysis(artifacts, case_id,case_mail_artifacts_analyzers) {
  let html = "";
  if (artifacts && artifacts.artifact) {
    for(let i = 0; i < artifacts.artifact.length; i++) {
      html += `
        <div class="card pt-2 pb-4 mb-4">
          <h4 class="title is-4 mt-2 ml-4 mb-1"><i class="fas fa-paperclip"></i> Artifact Analysis :</h4>
          `;
      if (Array.isArray(artifacts.artifact[i])) {
        html += `
        <p>${artifacts.artifact[i][0]}</p>
        `;
      } else {
        html += `
        <p>${artifacts.artifact[i]}</p>
        `;
      }

      html += renderArtifactScoreConfidenceLevel(artifacts.infos[i], case_id, i, 0);

      if (Array.isArray(artifacts.artifact[i])) {
        html += `
          <div class="button">
            <button class="button is-link" onclick="details_artifact('${artifacts.artifact[i][1]}');" id="mail_artifact_analyzers_button#${artifacts.artifact[i][1]}">More details <i class='fas fa-chevron-down'></i></button>
          </div>
          <div class="mail_artifact_analyzers" id="mail_artifact_analyzers#${artifacts.artifact[i][1]}" style="display: none;">
 `;
        html += renderArtifactAnalyzers(artifacts.artifact[i][0],case_mail_artifacts_analyzers, artifacts.artifact[i][2]);

        
        html += `</div>`;
        html += `</div>`;
      } else {
        html += `
          <div class="button">
            <button class="button is-link" onclick="details_artifact('${artifacts.artifact[i]}');" id="mail_artifact_analyzers_button#${artifacts.artifact[i]}">More details <i class='fas fa-chevron-down'></i></button>
          </div>
          <div class="mail_artifact_analyzers" id="mail_artifact_analyzers#${artifacts.artifact[i]}" style="display: none;">
          `;

          html += renderArtifactAnalyzers(artifacts.artifact[i],case_mail_artifacts_analyzers, 0);
        html += `</div>`;
        html += `</div>`;
      }
    }
  }
  return html;
}

function details_artifact(artifact) {
  let analyzers = document.getElementById("mail_artifact_analyzers#"+artifact);
  let analyzers_button = document.getElementById("mail_artifact_analyzers_button#"+artifact);
  if (analyzers.style.display == "none") {
    analyzers.style.display = "block";
    analyzers_button.innerHTML = "Less details <i class='fas fa-chevron-up'></i>";
  } else {
    analyzers.style.display = "none";
    analyzers_button.innerHTML = "More details <i class='fas fa-chevron-down'></i>";
  }
}

function renderArtifactScoreConfidenceLevel(info, case_id, index, innerIndex) {
  return `
    <div class="container">
      <div class="columns is-centered is-multiline dash mt-5">
        ${renderArtifactCard("Artifact Score", `${info[0]} / 10`, "artifactScore")}
        ${renderArtifactCard("Artifact Confidence", `${info[1]} %`, "artifactConf")}
        ${renderArtifactCard("Artifact Level", info[2].toUpperCase(), "artifactLevel")}
      </div>
    </div>`;
}

function renderArtifactAnalyzers(artifact,case_mail_artifacts_analyzers, url_vt_id) {
  let type = "search";
  let analyzersFound = [];

  if (artifact !== "" ) {
    case_mail_artifacts_analyzers.forEach((analyzer) => {
      if (Array.isArray(artifact)) {
        if (analyzer.artifact === artifact[0]) {
          analyzersFound.push(analyzer);
        }
      } else if (analyzer.artifact === artifact) {
        analyzersFound.push(analyzer);
      }
    });

    if (analyzersFound.length > 0) {
      if (url_vt_id != 0){
        type = "url";
        return `
        <div class="columns is-centered is-multiline">
          ${analyzersFound.map((analyzer, index) => {
            const {
              analyzer_name,
              status,
              score,
              confidence,
              level
            } = analyzer;
            return `
              ${renderAnalyzerCard(analyzer_name, status, score, confidence, level, `analyzer-${index}`, artifact, type, url_vt_id)}
            `;
          }).join('')}
        </div>`;
      }else{
        return `
        <div class="columns is-centered is-multiline">
          ${analyzersFound.map((analyzer, index) => {
            const {
              analyzer_name,
              status,
              score,
              confidence,
              level
            } = analyzer;
            return `
              ${renderAnalyzerCard(analyzer_name, status, score, confidence, level, `analyzer-${index}`, artifact, type, 0)}
            `;
          }).join('')}
        </div>`;
      }
    }
  }
  return `
  <div class="columns is-centered is-multiline">
    <div class="main column is-one-third">
      <div class="card">
        <div class="card-content">
          <div class="content">
            <p>No analyzers found</p>
          </div>
        </div>
      </div>
    </div>
  </div>
  `;
}

function renderArtifactCard(title, content, id) {
  return `
    <div class="main column is-narrow">
      <div class="card">
        <div class="card-content">
          <div class="content">
            <h2 class="title is-4">${title}</h2>
            <p id="${id}" class="subtitle is-6">${content}</p>
          </div>
        </div>
      </div>
    </div>`;
}
function renderArtifactButton(label, case_id, index, className) {
  return `
    <div class="button">
      <button class="button ${className}" data-case-id="${case_id}" id="artifact#${index}">Set As ${label}</button>
    </div>`;
}

function renderAttachmentsAnalysis(attachment, case_id,case_mail_attachments_analyzers) {
  let html = "";
  if (attachment) {
    attachment.attachment.forEach((currentAttachment, i) => {
      html += `
        <div class="card pt-2 pb-4 mb-4">
          <h4 class="title is-4 mt-2 ml-4 mb-1"><i class="fas fa-paperclip"></i> Attachment File Analysis :</h4>
          <p>${currentAttachment.file_name}</p>`;

      html += renderAttachmentScoreConfidenceLevel(attachment.infos[i].file_score, attachment.infos[i].file_confidence, attachment.infos[i].file_level);

      html += `
          <h4 class="title is-4 mt-2 ml-4 mb-1"><i class="fas fa-paperclip"></i> Attachment Hash Analysis :</h4>
          <p>${currentAttachment.linked_hash_value}</p>`;

      html += renderAttachmentHashScoreConfidenceLevel(attachment.infos[i].linked_hash_score, attachment.infos[i].linked_hash_confidence, attachment.infos[i].linked_hash_level);
      
      html += `
          <div class="button">
            <button class="button is-link" onclick="details_attachment('${currentAttachment.linked_hash_value}');" id="attachment_analyzers_button#${currentAttachment.linked_hash_value}">More details <i class='fas fa-chevron-down'></i></button>
          </div>
          <div class="attachment_analyzers" id="attachment_analyzers#${currentAttachment.linked_hash_value}" style="display: none;">`;

      html += renderAttachmentAnalyzers(currentAttachment, case_mail_attachments_analyzers);
      html += `</div>`;
      html += `</div>`;
    });
  }
  return html;
}




function details_attachment(attachment) {
  let analyzers = document.getElementById("attachment_analyzers#" + attachment);
  let analyzers_button = document.getElementById("attachment_analyzers_button#" + attachment);
  if (analyzers.style.display == "none") {
    analyzers.style.display = "block";
    analyzers_button.innerHTML = "Less details <i class='fas fa-chevron-up'></i>";
  } else {
    analyzers.style.display = "none";
    analyzers_button.innerHTML = "More details <i class='fas fa-chevron-down'></i>";
  }
}

function renderAttachmentHashScoreConfidenceLevel(score, confidence, level) {
  return `
    <div class="container">
      <div class="columns is-centered is-multiline dash mt-5">
        ${renderAttachmentCard("Score", score, "attachmentHashScore")}
        ${renderAttachmentCard("Confidence", `${confidence} %`, "attachmentHashConf")}
        ${renderAttachmentCard("Level", level.toUpperCase(), "attachmentHashLevel")}
      </div>
    </div>`;
}

function renderAttachmentAnalyzers(attachment, case_mail_attachments_analyzers) {

  let analyzerHtml = '';
  let foundAnalyzers = false;

  case_mail_attachments_analyzers.forEach(analyzer => {

    // Match analyzer based on linked_hash_value or file_name
    if (analyzer.artifact === attachment.linked_hash_value || analyzer.artifact === attachment.file_name) {
      foundAnalyzers = true;
      analyzerHtml += `
        <div class="main column is-one-third">
          <div class="card">
            <div class="card-content">
              <div class="content">
                <h2 class="title is-4">${analyzer.analyzer_name}</h2>
                <p>Status: ${analyzer.status}</p>
                <p>Score: ${analyzer.score}</p>
                <p>Confidence: ${analyzer.confidence}</p>
                <p>Level: ${analyzer.level}</p>
              </div>
            </div>
          </div>
        </div>`;
    }
  });

  if (!foundAnalyzers) {
    analyzerHtml = `
      <div class="columns is-centered is-multiline">
        <div class="main column is-one-third">
          <div class="card">
            <div class="card-content">
              <div class="content">
                <p>No analyzers found</p>
              </div>
            </div>
          </div>
        </div>
      </div>`;
  }

  return analyzerHtml;
}




function renderAttachmentScoreConfidenceLevel(score, confidence, level) {
  return `
    <div class="container">
      <div class="columns is-centered is-multiline dash mt-5">
        ${renderAttachmentCard("Attachment Score", score, "attachmentScore")}
        ${renderAttachmentCard("Attachment Confidence", `${confidence} %`, "attachmentConf")}
        ${renderAttachmentCard("Attachment Level", level.toUpperCase(), "attachmentLevel")}
      </div>
    </div>`;
}

function renderAttachmentCard(title, content, id) {
  return `
    <div class="main column is-narrow">
      <div class="card">
        <div class="card-content">
          <div class="content">
            <h2 class="title is-4">${title}</h2>
            <p id="${id}" class="subtitle is-6">${content}</p>
          </div>
        </div>
      </div>
    </div>`;
}

function renderChallengeSection(case_id, user, results) {
  return `
  <br/>
  <div class="card pt-2 pb-4 mb-4">
    <div id="divChall">
      <h4 class="title is-4 mt-2 ml-4 mb-1"><i class="fa-solid fa-hippo"></i> Challenge the results?</h4>
      <p>If you are not satisfied with the result you can challenge it to have another run</p>
      <div class="button">
        <input type="button" id="challenge" class="button is-link" value="Challenge">
        <input type="hidden" id="case_id" value="${case_id},${user},${results}">
      </div>
    </div>
  </div>`;
}

function renderCard(iconClass, title, content, id) {
  return `
    <div class="card pt-2 pb-4 mb-4">
      <h4 class="title is-4 mt-2 ml-4 mb-1"><i class="${iconClass}"></i> ${title}</h4>
      <p id="${id}">${content}</p>
    </div>`;
}

$("button.caseid").click(function () {
  id = $(this).val().split(",")[0];
  user = $(this).val().split(",")[1];
  
  openPop(id,user);  
});


function setIocLevel(id, type, level, button, case_id) {
  const endpoint = `../set-ioc-level/${id}/${type}/${level}/${case_id}`;

  fetch(endpoint)
  .then(response => {
    return response.json();
  })
  .then(result => {
      if (result.success) {
        handleSuccess(result, type, button);
      } else {
        handleFailure(result);
      }
    })
    .catch(error => {
      console.error(`Error in fetch: ${error}`);
    });
}

function handleSuccess(result, type, button) {
  const newScore = result.score;
  const newConfidence = result.confidence;
  const newLevel = result.level.toUpperCase();

  alert("Level set");

  const card = type === "attachment"
    ? button.parentElement.parentElement.parentElement
    : button.parentElement.parentElement;

  const card_score = card.querySelector(`#${type}Score`);
  const card_confidence = card.querySelector(`#${type}Conf`);
  const card_level = card.querySelector(`#${type}Level`);

  card_score.innerHTML = `${newScore} / 10`;
  card_confidence.innerHTML = `${newConfidence} %`;
  card_level.innerHTML = `${newLevel}`;
  
  if( type === "attachment" ){
    const card_hash_score = card.querySelector(`#${type}HashScore`);
    const card_hash_confidence = card.querySelector(`#${type}HashConf`);
    const card_hash_level = card.querySelector(`#${type}HashLevel`);

    card_hash_score.innerHTML = `${newScore} / 10`;
    card_hash_confidence.innerHTML = `${newConfidence} %`;
    card_hash_level.innerHTML = `${newLevel}`;

    const card_background = card_hash_level.parentElement.parentElement

    updateCardColors(type, newLevel, card_background);
  }

  const card_background = card_level.parentElement.parentElement;

  updateCardColors(type, newLevel, card_background);

  updateStatusAndResult(result, card);
}

function handleFailure(result) {
  console.error(`Server returned an error: ${result.error}`);
  // Add error handling logic as needed
}

function updateCardColors(type, level, card_background) {
  const colorMap = {
    MALICIOUS: "red",
    SUSPICIOUS: "orange",
    SAFE: "green",
  };

  const backgroundColor = colorMap[level] || "";

  card_background.style.backgroundColor = backgroundColor;
}

function updateStatusAndResult(result, card) {
  const cardStatus = document.getElementById("statusCase");
  const cardResult = document.getElementById("resultCase");
  const cardScore = document.getElementById("scoreCase");
  const cardConfidence = document.getElementById("confCase");

  const statusColors = {
    "On Going": "orange",
    "Done": "green",
    "Challenged": "turquoise",
    "To Do": "red",
  };

  const resultColors = {
    "FAILURE": "lightgrey",
    "SUSPICIOUS": "orange",
    "SAFE": "green",
    "SAFE-ALLOW_LISTED": "green",
    "INCONCLUSIVE": "lightsalmon",
    "DANGEROUS": "red",
  };

  cardStatus.style.color = statusColors[cardStatus.innerHTML] || "";

  cardResult.style.fontWeight = "bold";
  cardResult.innerHTML = result.case_infos.results.toUpperCase();
  cardResult.style.color = resultColors[cardResult.innerHTML] || "";

  cardScore.innerHTML = `${result.case_infos.score} / 10`;
  cardConfidence.innerHTML = `${result.case_infos.confidence} %`;
}
