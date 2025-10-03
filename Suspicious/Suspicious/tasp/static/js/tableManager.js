class TableManager {
  constructor(table, options = {}) {
    this.table =
      typeof table === "string" ? document.querySelector(table) : table;
    this.options = Object.assign(
      {
        debug: false,
        pagination: true,
        showRows: [5, 10, 50],
        defaultRows: 10,
        labels: {
          filter: "Filter by",
          showRows: "Show rows",
          noResult: "No result found",
        },
        controls: {
          toggleFilterSelector: ".btn-filter",
          moreFilterSelector: ".filterable .btn-morefilter",
          countSelector: "#num",
        },
      },
      options
    );

    this.currentPage = 0;
    this.rowsPerPage = this.options.defaultRows;
    this.init();
  }

  init() {
    this.tbody = this.table.querySelector("tbody");
    this.rows = Array.from(this.tbody.querySelectorAll("tr"));
    this.totalRows = this.rows.length;
    this.createRowSelector();
    if (this.options.pagination) {
      this.createPaginationControls();
      this.paginate();
    }

    this.updateVisibleCount();
    this.setupFilterToggles();
  }

  /** ------------ Pagination ------------- */
  createPaginationControls() {
    this.paginationDiv = document.createElement("div");
    this.paginationDiv.className = "pagination is-centered";
    this.table.insertAdjacentElement("afterend", this.paginationDiv);
    this.updatePaginationControls();
  }
  updatePaginationControls() {
    this.paginationDiv.innerHTML = "";
    const numPages = Math.ceil(this.totalRows / this.rowsPerPage);

    const createBtn = (text, value, extraClass = "") => {
      const btn = document.createElement("button");
      btn.textContent = text;
      btn.dataset.page = value;
      btn.className = `pagecontroller ${extraClass}`;
      btn.addEventListener("click", () => this.handlePageClick(value));
      return btn;
    };

    // Boutons fixes
    const firstBtn = createBtn(
      "<<",
      "first",
      "pagination-link pagecontroller-f"
    );
    const prevBtn = createBtn(
      "<",
      "prev",
      "pagination-previous pagecontroller-p"
    );
    const nextBtn = createBtn(">", "next", "pagination-next pagecontroller-n");
    const lastBtn = createBtn(">>", "last", "pagination-link pagecontroller-l");
    if (this.currentPage === 0) {
      firstBtn.classList.add("is-disabled");
      prevBtn.classList.add("is-disabled");
    }
    if (this.currentPage === numPages - 1) {
      nextBtn.classList.add("is-disabled");
      lastBtn.classList.add("is-disabled");
    }
    this.paginationDiv.append(firstBtn, prevBtn);

    // Boutons de pages
    const pageButtons = [];
    for (let i = 0; i < numPages; i++) {
      const btn = createBtn(i + 1, i, "pagination-link pagecontroller-num");
      if (i === this.currentPage) btn.classList.add("is-current");
      pageButtons.push(btn);
    }

    // Affiche les 2 premiers
    if (pageButtons[0]) this.paginationDiv.append(pageButtons[0]);
    if (pageButtons[1]) this.paginationDiv.append(pageButtons[1]);

    // Si plus de 5 pages → ajoute un <select> au milieu
    if (numPages > 5) {
      const selectDiv = document.createElement("div");
      selectDiv.className = "select";
      const pageSelector = document.createElement("select");

      const defaultOption = document.createElement("option");
      defaultOption.value = "";
      defaultOption.text = "...";
      defaultOption.disabled = true;

      // cas extrémités → "..." sélectionné
      if (this.currentPage <= 1 || this.currentPage >= numPages - 2) {
        defaultOption.selected = true;
      }
      pageSelector.appendChild(defaultOption);

      let middleActive = false;
      for (let i = 1; i <= numPages; i++) {
        const option = document.createElement("option");
        option.value = i - 1;
        option.text = `Page ${i}`;

        // Si page courante au milieu → sélectionne la page courante
        if (
          this.currentPage > 1 &&
          this.currentPage < numPages - 2 &&
          this.currentPage === i - 1
        ) {
          option.selected = true;
          middleActive = true;
        }

        pageSelector.appendChild(option);
      }

      // Ajoute 'is-link' si au milieu
      if (middleActive) {
        selectDiv.classList.add("is-link");
      }

      pageSelector.addEventListener("change", (e) => {
        this.currentPage = parseInt(e.target.value, 10);
        this.paginate();
        this.updatePaginationControls();
      });

      selectDiv.appendChild(pageSelector);
      this.paginationDiv.append(selectDiv);
    } else if (numPages == 5) {
      if (pageButtons[2]) this.paginationDiv.append(pageButtons[2]);
    }

    // Ajoute les 2 dernières pages
    if (pageButtons[numPages - 2])
      this.paginationDiv.append(pageButtons[numPages - 2]);
    if (pageButtons[numPages - 1])
      this.paginationDiv.append(pageButtons[numPages - 1]);

    this.paginationDiv.append(nextBtn, lastBtn);
  }

  handlePageClick(value) {
    const numPages = Math.ceil(this.totalRows / this.rowsPerPage);

    if (value === "first") this.currentPage = 0;
    else if (value === "last") this.currentPage = numPages - 1;
    else if (value === "prev" && this.currentPage > 0) this.currentPage--;
    else if (value === "next" && this.currentPage < numPages - 1)
      this.currentPage++;
    else if (!isNaN(value)) this.currentPage = parseInt(value, 10);

    this.paginate();
    this.updatePaginationControls();
  }

  paginate() {
    const start = this.currentPage * this.rowsPerPage;
    const end = start + this.rowsPerPage;

    this.rows.forEach((row, i) => {
      row.style.display = i >= start && i < end ? "" : "none";
    });
  }

  /** ------------ Row selector ------------- */
  createRowSelector() {
    const container = document.createElement("div");
    container.className = "field is-grouped is-grouped-multiline";

    const selectWrapper = document.createElement("div");
    selectWrapper.className = "select is-rounded is-primary";

    const select = document.createElement("select");

    this.options.showRows.forEach((num) => {
      const option = document.createElement("option");
      option.value = num;
      option.textContent = `${this.options.labels.showRows}: ${num}`;
      if (num === this.rowsPerPage) option.selected = true;
      select.appendChild(option);
    });

    select.addEventListener("change", (e) => {
      this.rowsPerPage = parseInt(e.target.value, 10);
      this.currentPage = 0;
      if (this.options.pagination) {
        this.paginate();
        this.updatePaginationControls();
      } else {
        this.showFilteredRowsOnly();
      }
      this.updateVisibleCount();
    });

    selectWrapper.appendChild(select);
    container.append(selectWrapper);
    this.table.insertAdjacentElement("afterend", container);
  }

  /* ---------------- Filters ---------------- */

  createFiltersRow() {
    if (!this.theadRow) return;
    const colCount = this.theadRow.cells.length;

    const filterRow = document.createElement("tr");
    filterRow.className = "filters";

    // Initialiser activeFilters si pas déjà fait
    if (!this.activeFilters) this.activeFilters = Array(colCount).fill("");

    for (let colIdx = 0; colIdx < colCount; colIdx++) {
      const th = document.createElement("th");
      const input = document.createElement("input");
      input.type = "text";
      input.placeholder = this.options.labels.filter || "";
      input.disabled = true;
      input.dataset.col = String(colIdx);

      input.addEventListener("input", () => {
        // Mettre à jour le tableau des filtres
        this.activeFilters[colIdx] = input.value.toLowerCase();
        this.applyAllFilters();
      });

      th.appendChild(input);
      filterRow.appendChild(th);
    }
    this.theadRow.parentNode.appendChild(filterRow);
  }
  setupFilterToggles() {
    const toggleBtn = document.querySelector(
      this.options.controls.toggleFilterSelector
    );
    const moreBtn = document.querySelector(
      this.options.controls.moreFilterSelector
    );
    let count = 1;
    let count2 = 1;

    if (toggleBtn) {
      toggleBtn.addEventListener("click", () => {
        const inputs = this.table.querySelectorAll(".filters input");
        const tbodyRows = Array.from(this.tbody.querySelectorAll("tr"));

        if (!(count % 2 === 0)) {
          // Enable filters
          if (inputs[0].disabled) {
            inputs.forEach((inp) => (inp.disabled = false));
            inputs[0]?.focus();
          } else {
            // Disable & clear filters
            inputs.forEach((inp) => {
              inp.disabled = true;
              inp.value = "";
            });
            this.removeNoResultRow();
            tbodyRows.forEach((r) => (r.style.display = ""));
          }

          // Attach dynamic keyup listener
          inputs.forEach((input, colIdx) => {
            input.onkeyup = (e) => {
              const term = input.value.toLowerCase();
              let anyHidden = false;

              tbodyRows.forEach((row) => {
                const cell = row.cells[colIdx];
                if (!cell) return;
                if (!cell.textContent.toLowerCase().includes(term)) {
                  row.style.display = "none";
                  anyHidden = true;
                } else {
                  row.style.display = "";
                }
              });

              // No-result row
              const visibleRows = tbodyRows.filter(
                (r) => r.style.display !== "none"
              );
              if (visibleRows.length === 0) {
                const colCount = this.theadRow?.cells.length ?? 0;
                this.insertNoResultRow(colCount);
              } else {
                this.removeNoResultRow();
              }

              // Update visible count
              this.updateVisibleCount();
            };
          });
        } else {
          // Disable & clear filters
          inputs.forEach((inp) => {
            inp.disabled = true;
            inp.value = "";
          });
          this.activeFilters = [];
          this.removeNoResultRow();

          // Restore the currently paginated page
          if (this.options.pagination) {
            this.paginate(); // shows only current page rows
            this.updatePaginationControls(); // update pagination buttons
          } else {
            this.showAllRows(); // fallback if no pagination
          }

          this.updateVisibleCount();
        }

        count += 1;
      });
    }

    if (moreBtn) {
      moreBtn.addEventListener("click", () => {
        if (count2 % 2 === 0 && this.options.pagination) {
          this.updatePaginationControls();
        }
        count2 += 1;
      });
    }
  }

  applyAllFilters() {
    if (!this.tbody) return;

    const colCount = this.theadRow?.cells.length ?? 0;

    // Initialiser filteredRows sur toutes les lignes si non fait
    this.filteredRows = this.rows.filter((row) => {
      for (let c = 0; c < colCount; c++) {
        const term = (this.activeFilters[c] || "").trim();
        if (!term) continue;
        const cellText = (row.cells[c]?.textContent || "").toLowerCase();
        if (!cellText.includes(term)) return false;
      }
      return true;
    });

    // Affichage "no result"
    if (this.filteredRows.length === 0) {
      this.insertNoResultRow(colCount);
    } else {
      this.removeNoResultRow();
    }

    // Re-paginate
    this.currentPage = 0;
    if (this.options.pagination) this.paginate();
    else this.showFilteredRowsOnly();

    this.updateVisibleCount();
  }

  insertNoResultRow(colspan) {
    this.removeNoResultRow();
    const tr = document.createElement("tr");
    tr.className = "no-result text-center";
    const td = document.createElement("td");
    td.colSpan = colspan;
    td.textContent = this.options.labels.noResult;
    tr.appendChild(td);
    this.tbody.prepend(tr);
  }

  removeNoResultRow() {
    const nr = this.tbody.querySelector("tr.no-result");
    if (nr) nr.remove();
  }

  showFilteredRowsOnly() {
    const set = new Set(this.filteredRows);
    this.rows.forEach((r) => (r.style.display = set.has(r) ? "" : "none"));
  }

  showAllRows() {
    this.rows.forEach((r) => (r.style.display = ""));
  }

  updateVisibleCount() {
    const countEl = document.querySelector(this.options.controls.countSelector);
    if (!countEl) return;
    // Count only visible tbody rows, exclude any “no-result” placeholder
    const visible = Array.from(this.tbody.querySelectorAll("tr")).filter(
      (tr) => tr.style.display !== "none" && !tr.classList.contains("no-result")
    );
    countEl.textContent = String(visible.length);
  }
}
