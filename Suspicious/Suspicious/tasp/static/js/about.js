document.addEventListener("DOMContentLoaded", () => {
  const modals = document.querySelectorAll(".modal");
  const modalTriggers = document.querySelectorAll(".js-modal-triggers");
  const modalCloseSelectors = [
    ".modal-background",
    ".modal-close",
    ".modal-card-head .delete",
    ".modal-card-foot .button"
  ];

  const openModal = (modal) => modal?.classList.add("is-active");
  const closeModal = (modal) => modal?.classList.remove("is-active");
  const closeAllModals = () => modals.forEach(closeModal);

  modalTriggers.forEach((trigger) => {
    const modalId = trigger.dataset.target;
    const targetModal = document.getElementById(modalId);

    if (!targetModal) {
      console.warn(`Modal with id '${modalId}' does not exist.`);
      return;
    }

    trigger.addEventListener("click", () => openModal(targetModal));
  });

  document.querySelectorAll(modalCloseSelectors.join(", ")).forEach((el) => {
    el.addEventListener("click", () => {
      const modal = el.closest(".modal");
      closeModal(modal);
    });
  });

  document.addEventListener("keydown", ({ key }) => {
    if (key === "Escape") closeAllModals();
  });
});
