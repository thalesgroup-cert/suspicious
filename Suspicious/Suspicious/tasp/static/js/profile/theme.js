const saveTheme = async () => {
  const selectedTheme = document.getElementById("themeSelect").value;

  try {
    const response = await fetch("../update-appearance/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ theme: selectedTheme }),
    });

    const result = await response.json();

    if (result.success) {
      console.log("Theme updated successfully");
      // Immediately apply theme to <html>
      document.documentElement.setAttribute("data-theme", selectedTheme);
    } else {
      console.error("Error updating theme:", result.message);
    }
  } catch (error) {
    console.error("Error updating theme:", error);
  }
};


$(document).ready(function () {
  document.getElementById("saveTheme").addEventListener("click", saveTheme);
});