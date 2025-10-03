document.addEventListener("DOMContentLoaded", () => {
  const inputs = document.querySelectorAll(".input-box");

  inputs.forEach((input) => {
    input.addEventListener("change", () => {
      let value = parseFloat(input.value);

      if (isNaN(value) || value < 0) {
        value = 0;
      } else if (value > 1) {
        value = 1;
      }

      input.value = value;
      updateAnalyzerWeight(input.id, value);
    });
  });
});

function createAnalyzerInputs(analyzerId) {
  const input = document.getElementById(analyzerId);
  const decrementBtn = input?.previousElementSibling;
  const incrementBtn = input?.nextElementSibling;

  decrementBtn?.addEventListener("click", () => {
    let value = parseFloat(input.value);
    if (value > 0) {
      value = Math.max(0, value - 0.1).toFixed(1);
      input.value = value;
      updateAnalyzerWeight(analyzerId, value);
    }
  });

  incrementBtn?.addEventListener("click", () => {
    let value = parseFloat(input.value);
    if (value < 1) {
      value = Math.min(1, value + 0.1).toFixed(1);
      input.value = value;
      updateAnalyzerWeight(analyzerId, value);
    }
  });
}

async function updateAnalyzerWeight(analyzerId, weight) {
  try {
    const response = await fetch(
      `../update-analyzer-weight/${analyzerId}/${weight}/`,
      {
        method: "POST",
      }
    );

    if (!response.ok) throw new Error(`HTTP error: ${response.status}`);
    await response.json();
  } catch (error) {
    console.error("Error updating analyzer weight:", error);
  }
}
