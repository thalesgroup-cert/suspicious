document.addEventListener("DOMContentLoaded", () => {
  const modals = document.querySelectorAll(".modal");
  const modalTriggers = document.querySelectorAll(".js-modal-triggers");
  const modalCloseElements = document.querySelectorAll(
    ".modal-background, .modal-close, .modal-card-head .delete, .modal-card-foot .button"
  );

  const openModal = ($el) => $el.classList.add("is-active");
  const closeModal = ($el) => $el.classList.remove("is-active");
  const closeAllModals = () => modals.forEach(closeModal);

  modalTriggers.forEach(($trigger) => {
    const modalId = $trigger.dataset.target;
    const $target = document.getElementById(modalId);
    if (!$target) {
      console.warn(`Modal with id ${modalId} does not exist`);
      return;
    }
    $trigger.addEventListener("click", () => openModal($target));
  });

  modalCloseElements.forEach(($close) => {
    $close.addEventListener("click", () => {
      const $target = $close.closest(".modal");
      closeModal($target);
    });
  });

  document.addEventListener("keydown", (event) => {
    if (event.keyCode === 27) {
      // Escape key
      closeAllModals();
    }
  });
});



function changeDashboard() {
  // get chart
  const chart = document.getElementById("myChart");
  // get value of select
  const monthNew = parseInt(document.getElementById("monthc").value);
  const yearNew = parseInt(document.getElementById("yearc").value);

  const newUser = document.getElementById("newUsers");
  const totalUser = document.getElementById("totalUsers");
  const totalCases = document.getElementById("totalCases");

  const failure = document.getElementById("failurep");
  const safe = document.getElementById("safep");
  const suspicious = document.getElementById("suspiciousp");
  const inconclusive = document.getElementById("inconclusivep");
  const dangerous = document.getElementById("dangerousp");



  fetch(`/dashboard-change/${monthNew}/${yearNew}`)
    .then((response) => response.json())
    .then((data) => {
      $('#myChart').remove();
      $('.content.chart').prepend('<canvas id = "myChart"></canvas>');
      const print = "true";
      // get labels
      const labels = data.labels;
      // get data
      const dataValues = data.data;
      // draw chart
      h2 = document.getElementById("subtitle");
      h2.innerHTML = `Dashboard for : ${monthNew}/${yearNew}`;
      drawDashboard(print, dataValues, labels);

      newUser.innerHTML = data.new_users;
      totalUser.innerHTML = data.total_reporters;
      totalCases.innerHTML = data.total_cases;

      failure.innerHTML = data.stats.failure;
      safe.innerHTML = data.stats.safe;
      suspicious.innerHTML = data.stats.suspicious;
      inconclusive.innerHTML = data.stats.inconclusive;
      dangerous.innerHTML = data.stats.dangerous;


    });
}


const drawDashboard = (print, data, labels) => {
  if (print) {
    const canvas = document.getElementById('myChart');

    const chartData = {
      axis: 'y',
      labels,
      datasets: [{
        label: 'Reports',
        data,
        fill: false,
        backgroundColor: '#5ec0d5',
        borderColor: '#5ec0d5',
        borderWidth: 1,
      }],
    };

    const chartOptions = {
      indexAxis: 'y',
      elements: {
        bar: {
          borderWidth: 2,
        },
      },
      responsive: true,
      maintainAspectRatio: false,
      legend: {
        labels: {
          fontColor: 'blue',
          fontSize: 12,
        },
      },
      plugins: {
        legend: {
          position: 'right',
        },
        title: {
          display: true,
          text: 'Top 10 reporters',
        },
      },
    };

    const chartConfig = {
      type: 'bar',
      data: chartData,
      options: chartOptions,
    };

    const myChart = new Chart(canvas, chartConfig);
  }
};


const elements = document.getElementsByClassName("card-content");


for (let i = 0; i < elements.length; i++) {
let value = elements[i].id.toUpperCase();
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
    case "DANGEROUS":
      color = "red";
      break;
    default:
      break;
}

if (color) {
  elements[i].style.backgroundColor = color;
}
}