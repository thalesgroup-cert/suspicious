document.addEventListener("DOMContentLoaded", () => {
  const toggleSwitch = document.getElementById("email-feeder-toggle");
  const feederStatus = document.getElementById("feeder-status");

  const setStatusText = (status) => {
    feederStatus.innerText = `Current Status: ${status}`;
  };

  const getCsrfToken = () => {
    const match = document.cookie.match(/csrftoken=([^;]+)/);
    return match ? match[1] : null;
  };

  const getEmailFeederStatus = async () => {
    try {
      const response = await fetch("/get-email-feeder-status/", {
        headers: { "Content-Type": "application/json" },
      });
      const data = await response.json();

      if (data.status === true) {
        toggleSwitch.checked = true;
        setStatusText("ON");
      } else if (data.status === false) {
        toggleSwitch.checked = false;
        setStatusText("OFF");
      } else {
        setStatusText("Unknown");
        console.warn("Feeder status is unknown");
      }
    } catch (error) {
      console.error("Error fetching status:", error);
      setStatusText("Unknown");
    }
  };

  const toggleEmailFeeder = async () => {
    const isChecked = toggleSwitch.checked;

    try {
      const response = await fetch("/toggle-email-feeder/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": getCsrfToken(),
        },
        body: JSON.stringify({ status: isChecked }),
      });
      const data = await response.json();
      setStatusText(data.status ? "ON" : "OFF");
    } catch (error) {
      console.error("Error toggling email feeder:", error);
      setStatusText("Error toggling status");
    }
  };

  getEmailFeederStatus();
  toggleSwitch.addEventListener("change", toggleEmailFeeder);
});
