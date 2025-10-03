       
$(function() {
  const navbarBurger = $(".navbar-burger");
  const navbarMenu = $(".navbar-menu-burger");

  navbarBurger.on("click", function() {
    navbarBurger.toggleClass("is-active");
    navbarMenu.toggle();
  });
});

document.addEventListener("DOMContentLoaded", () => {
  const modals = document.querySelectorAll(".modal");
  const modalCloseElements = document.querySelectorAll(
    ".modal-background, .modal-close, .modal-card-head .delete, .modal-card-foot .button"
  );
  const autoTriggerModal = document.querySelector(".js-auto-trigger-modal");  // Auto trigger modal on page load

  const openModal = ($el) => $el.classList.add("is-active");
  const closeModal = ($el) => $el.classList.remove("is-active");
  const closeAllModals = () => modals.forEach(closeModal);

  if (autoTriggerModal) {
    const modalId = autoTriggerModal.dataset.target;
    const $target = document.getElementById("updateProfile");
    if (!$target) {
      console.warn(`Modal with id ${modalId} does not exist`);
      return;
    }
    openModal($target);
  }

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


function addScope() {
  let region = document.getElementById("region");
  let country = document.getElementById("country");
  let gbu = document.getElementById("gbu").value;

  if (region.checked) {
    region = region.value;
    country = "";
  } else {
    region = "";
    country = country.value;
  }


  let scope = region + country + " | " + gbu;
  fetch(`../update-ciso-profile-scope/${scope}`)
        .then(response => response.json())
        .then(result => {
          if (result.success) {
            // remove the div with id scope's content
            let scopeDiv = document.getElementById("scope");
            scopeDiv.innerHTML = "";
            // create a new div content to thank the user for updating the scope
            let newDiv = document.createElement("div");
            newDiv.innerHTML = "Thank you for updating your scope!";
            scopeDiv.appendChild(newDiv);
            // remove the div updateProfile after 3 seconds
            setTimeout(function() {
              let updateProfile = document.getElementById("updateProfile");
              updateProfile.remove();
              window.location.reload();
            }
            , 3000);
          }
        });
}

function logOut() {
  fetch("../logout")
        .then(response => response.json())
        .then(result => {
          if (result.success) {
            window.location.href = "/";
          }
        });
}

document.addEventListener("DOMContentLoaded", () => {
  const countryField = document.getElementById('country');
  const regionField = document.getElementById('region');

  if (countryField && regionField) {
    countryField.addEventListener('change', () => {
      if (countryField.checked) {
        regionField.disabled = true;
      } else {
        regionField.disabled = false;
      }
    });

    regionField.addEventListener('change', () => {
      if (regionField.checked) {
        countryField.disabled = true;
      } else {
        countryField.disabled = false;
      }
    });
  }
});