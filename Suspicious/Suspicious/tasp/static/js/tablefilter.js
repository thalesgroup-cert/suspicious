(function ($) {
  // you can have initial casses
  const table = document.getElementById("table");
  const tr = table.getElementsByTagName("tr");
  const td = table.getElementsByTagName("td");
  const elem = $("tr:visible td").get();
  const columns = $("select#column").get();
  const operators = $("select#operator").get();
  const operatorsId = $("select#Idoperator").get();
  const operatorsDate = $("select#Dateoperator").get();
  const operatorsStatus = $("select#Soperator").get();
  const operatorsResult = $("select#Roperator").get();
  var callbacks = {};
  var callbacksCol = {};
  function createArrayClassedTd() {
    const td = [];
    // Dynamically determine the number of columns
    const numColumns = columns.length > 0 ? columns[0].length : 0;
    // Loop through each row and column
    for (let i = 0; i < elem.length; i += numColumns) {
      const row = [];
      for (let j = 0; j < numColumns; j++) {
        row.push(elem[i + j].textContent.toUpperCase());
      }
      td.push(row);
    }
    const classedTd = [];
    // Loop through each column value dynamically
    for (let i = 0; i < numColumns; i++) {
      const columnValues = [];
      for (let j = 0; j < td.length; j++) {
        columnValues.push(td[j][i]);
      }
      classedTd.push([columns[0][i].value.toUpperCase(), columnValues]);
    }
    return classedTd;
  }
  function filterDataText(columns, indice, filters) {
    const classedTd = createArrayClassedTd();
    const tdLength = classedTd[0][1].length;
    for (let i = 0; i < columns.length; i++) {
      const indicesCol = columns[i];
      for (let m = 0; m < indicesCol.length; m++) {
        const indiceCol = indicesCol[m].value.toUpperCase();
        addCol(indiceCol, function () {
          for (let j = 0; j < tdLength; j++) {
            let isDisplay = true;
            for (let t = 0; t < filters.length; t++) {
              const value = classedTd[m][1][j].toUpperCase();
              switch (indice) {
                case "OPEC":
                  isDisplay = isDisplay && value.includes(filters[t].value.toUpperCase());
                  break;
                case "OPEDC":
                  isDisplay =
                    isDisplay && !value.includes(filters[t].value.toUpperCase());
                  break;
                case "OPEI":
                  isDisplay =
                    isDisplay && value === filters[t].value.toUpperCase();
                  break;
                case "OPEIN":
                  isDisplay =
                    isDisplay && !(value === filters[t].value.toUpperCase());
                  break;
                case "OPESW":
                  isDisplay =
                    isDisplay && value.startsWith(filters[t].value.toUpperCase());
                  break;
                case "OPEEW":
                  isDisplay =
                    isDisplay && value.endsWith(filters[t].value.toUpperCase());
                  break;
                default:
                  break;
              }
            }
            tr[j + 1].style.display = isDisplay ? "" : "none";
          }
        });
      }
    }
  }
  function filterDataEnum(id, columns, indice, context) {
    const classedTd = createArrayClassedTd();
    const tdLength = classedTd[0][1].length;
    for (let i = 0; i < columns.length; i++) {
      const indicesCol = columns[i];
      for (let j = 0; j < tdLength; j++) {
        let isDisplay = true;
        const value = classedTd[id][1][j].toUpperCase();
        switch (indice) {
          case "OPEI":
            isDisplay = value === context;
            break;
          case "OPEIN":
            isDisplay = value !== context;
            break;
          default:
            break;
        }
        tr[j + 1].style.display = isDisplay ? "" : "none";
      }
    }
  }
  function filterDataNum(id, columns, indice, filters) {
    const classedTd = createArrayClassedTd();
    const tdLength = classedTd[0][1].length;
    for (let i = 0; i < columns.length; i++) {
      const indicesCol = columns[i];
      for (let j = 0; j < tdLength; j++) {
        let isDisplay = true;
        let value;
        for (let t = 0; t < filters.length; t++) {
          value = parseInt(classedTd[id][1][j]);
          switch (indice) {
            case "OPEEQ":
              isDisplay = isDisplay && value == parseInt(filters[t].value);
              break;
            case "OPENEQ":
              isDisplay = isDisplay && value != parseInt(filters[t].value);
              break;
            case "OPELT":
              isDisplay = isDisplay && value < parseInt(filters[t].value);
              break;
            case "OPEGT":
              isDisplay = isDisplay && value > parseInt(filters[t].value);
              break;
            case "OPELE":
              isDisplay = isDisplay && value <= parseInt(filters[t].value);
              break;
            case "OPEGE":
              isDisplay = isDisplay && value >= parseInt(filters[t].value);
              break;
            default:
              break;
          }
        }
        tr[j + 1].style.display = isDisplay ? "" : "none";
      }
    }
  }
  function getDateFromContext(context) {
    let date;
    let dateCheck;
    if (context == "TODAY") {
      date = new Date();
    } else if (context == "YEST") {
        date = new Date();
        date.setDate(date.getDate() - 1);
    } else if (context == "LAST7") {
        date = new Date();
        date.setDate(date.getDate() - 7);
    } else if (context == "LAST30") {
        date = new Date();
        date.setDate(date.getDate() - 30);
    } else if (context == "CURRM") {
        dateCheck = new Date().getMonth();
    } else if (context == "CURRY") {
        dateCheck = new Date().getFullYear();
    } else if (context == "YEAR") {
        dateCheck = parseInt(document.getElementById("filterYear").value);
    } else if (context == "EXADA") {
        date = new Date(document.getElementById("filterDate").value);
    }
    return date || dateCheck;
  }
  function operator() {
    for (let index = 0; index < operators.length; index++) {
      let indices = operators[index];
      for (let k = 0; k < indices.length; k++) {
        let indice = indices[k].value.toUpperCase();
        add(indice, function () {
          var filters = $(".filter").get();
          filterDataText(columns, indice, filters);
        });
      }
    }
  }
  function operatorId() {
    const classedTd = createArrayClassedTd();
    for (let index = 0; index < operatorsId.length; index++) {
      let indices = operatorsId[index];
      for (let k = 0; k < indices.length; k++) {
        let indice = indices[k].value.toUpperCase();
        addId(indice, function () {
          var filters = $(".filterId").get();
          let id = findIndexIn2DArray(classedTd, "ID");
          filterDataNum(id, columns, indice, filters);
        });
      }
    }
  }
  function operatorTest() {
    const classedTd = createArrayClassedTd();
    for (let index = 0; index < operatorsId.length; index++) {
      let indices = operatorsId[index];
      for (let k = 0; k < indices.length; k++) {
        let indice = indices[k].value.toUpperCase();
        addTest(indice, function () {
          var filters = $(".filterId").get();
          let id = findIndexIn2DArray(classedTd, "TESTS");
          filterDataNum(id, columns, indice, filters);
        });
      }
    }
  }
  function operatorDate() {
    const classedTd = createArrayClassedTd();
    let id = findIndexIn2DArray(classedTd, "DATE");
    for (let index = 0; index < operatorsDate.length; index++) {
      let indices = operatorsDate[index];
      for (let k = 0; k < indices.length; k++) {
        let indice = indices[k].value.toUpperCase();
        addDate(indice, function () {
          var filters = $(".filterDate").get();
          const tdLength = classedTd[0][1].length;
          let opeDates = $("select#DateContext").get();
          for (let index = 0; index < opeDates.length; index++) {
            let context = opeDates[index].value.toUpperCase();
            const date = getDateFromContext(context);
            let isDisplay = true;
            for (j = 0; j < tdLength; j++) {
              const dateTd = new Date(classedTd[id][1][j]);
              switch (indice) {
                case "OPEI":
                    if (context == "CURRY" || context == "CURRM" || context == "YEAR") {
                      if (context == "CURRY") {
                          isDisplay = isDisplay && date == dateTd.getFullYear();
                      } else if (context == "YEAR") {
                          isDisplay = isDisplay && date == dateTd.getFullYear();
                      } else {
                          isDisplay = isDisplay && date == dateTd.getMonth();
                      }
                    } else {
                      isDisplay = isDisplay && date.getDate() == dateTd.getDate();
                    }
                    break;
                case "OPEIN":
                    if (context == "CURRY" || context == "CURRM" || context == "YEAR") {
                      if (context == "CURRY") {
                          isDisplay = isDisplay && date != dateTd.getFullYear();
                      } else if (context == "YEAR") {
                          isDisplay = isDisplay && date != dateTd.getFullYear();
                      } else {
                          isDisplay = isDisplay && date != dateTd.getMonth();
                      }
                    } else {
                      isDisplay = dateTd.getDate() != date.getDate();
                    }
                    break;
                case "OPEIB":
                    dateIsBefore = new Date(document.getElementById("filterDate").value);
                    isDisplay =dateTd < dateIsBefore && dateTd.getDate() != dateIsBefore.getDate();
                    break;
                case "OPEIA":
                    dateIsAfter = new Date(document.getElementById("filterDate").value);
                    isDisplay = dateTd > dateIsAfter && dateTd.getDate() != dateIsAfter.getDate();
                    break;
                case "OPEOB":
                    dateIsOnOrBefore = new Date(document.getElementById("filterDate").value);
                    isDisplay = dateTd <= dateIsOnOrBefore || (dateTd.getDate() == dateIsOnOrBefore.getDate() && dateTd.getMonth() == dateIsOnOrBefore.getMonth());
                    break;
                case "OPEOA":
                    dateIsOnOrAfter = new Date(document.getElementById("filterDate").value);
                    isDisplay = dateTd >= dateIsOnOrAfter || (dateTd.getDate() == dateIsOnOrAfter.getDate() && dateTd.getMonth() == dateIsOnOrAfter.getMonth());
                    break;
                default:
                    break;
              }
              tr[j + 1].style.display = isDisplay ? "" : "none";
            }
          }
        });
      }
    }
  }
  function findIndexIn2DArray(arr, val) {
    for (let i = 0; i < arr.length; i++) {
      if (arr[i][0] === val) {
        return i;
      }
    }
    return -1; // return -1 if val is not found in the first index of any element in the array
  }
  function operatorStatus() {
    const classedTd = createArrayClassedTd();
    for (let index = 0; index < operatorsStatus.length; index++) {
      let indices = operatorsStatus[index];
      for (let k = 0; k < indices.length; k++) {
        let indice = indices[k].value.toUpperCase();
        addStatus(indice, function () {
          let opeStatus = $("select#SContext").get();
          for (let index = 0; index < opeStatus.length; index++) {
            let context = opeStatus[index].value.toUpperCase();
            let id = findIndexIn2DArray(classedTd, "STATUS");
            filterDataEnum(id, columns, indice, context);
          }
        });
      }
    }
  }
  function operatorResult() {
    const classedTd = createArrayClassedTd();
    for (let index = 0; index < operatorsResult.length; index++) {
      let indices = operatorsResult[index];
      for (let k = 0; k < indices.length; k++) {
        let indice = indices[k].value.toUpperCase();
        addResult(indice, function () {
          let opeResult = $("select#RContext").get();
          for (let index = 0; index < opeResult.length; index++) {
            let context = opeResult[index].value.toUpperCase();
            let id = findIndexIn2DArray(classedTd, "RESULT");
            filterDataEnum(id, columns, indice, context);
          }
        });
      }
    }
  }
  function add(_case, fn) {
    callbacks[_case] = callbacks[_case] || [];
    callbacks[_case].push(fn);
  }
  function pseudoSwitch(value) {
    if (callbacks[value]) {
      callbacks[value].forEach(function (fn) {
        fn();
      });
    }
  }
  function pseudoSwitchCol(value) {
    if (callbacksCol[value]) {
      callbacksCol[value].forEach(function (fnCol) {
        fnCol();
      });
    }
  }
  function addCol(_caseCol, fnCol) {
    callbacksCol[_caseCol] = callbacksCol[_caseCol] || [];
    callbacksCol[_caseCol].push(fnCol);
  }
  //ID
  function addId(_case, fn) {
    callbacks[_case] = callbacks[_case] || [];
    callbacks[_case].push(fn);
  }
  function pseudoSwitchId(value) {
    if (callbacks[value]) {
      callbacks[value].forEach(function (fn) {
        fn();
      });
    }
  }
  function pseudoSwitchColId(value) {
    if (callbacksCol[value]) {
      callbacksCol[value].forEach(function (fnCol) {
        fnCol();
      });
    }
  }
  function addTest(_case, fn) {
    callbacks[_case] = callbacks[_case] || [];
    callbacks[_case].push(fn);
  }
  //DATE
  function addDate(_case, fn) {
    callbacks[_case] = callbacks[_case] || [];
    callbacks[_case].push(fn);
  }
  function pseudoSwitchDate(value) {
    if (callbacks[value]) {
      callbacks[value].forEach(function (fn) {
        fn();
      });
    }
  }
  //Status
  function addStatus(_case, fn) {
    callbacks[_case] = callbacks[_case] || [];
    callbacks[_case].push(fn);
  }
  function pseudoSwitchStatus(value) {
    if (callbacks[value]) {
      callbacks[value].forEach(function (fn) {
        fn();
      });
    }
  }
  //Result
  function addResult(_case, fn) {
    callbacks[_case] = callbacks[_case] || [];
    callbacks[_case].push(fn);
  }
  function pseudoSwitchResult(value) {
    if (callbacks[value]) {
      callbacks[value].forEach(function (fn) {
        fn();
      });
    }
  }
  function updateNum() {
    const elem = $("tr:visible").get();
    num.innerHTML = elem.length - 1;
  }
  $("input.submit").click(function () {
    const row = document.getElementById("column").value.toUpperCase();
    switch (row) {
      case "ID":
        const opeId = document.getElementById("Idoperator").value.toUpperCase();
        operatorId();
        pseudoSwitchId(opeId);
        pseudoSwitchColId(row);
        updateNum();
        break;
      case "TESTS":
        const opeTest = document
          .getElementById("Idoperator")
          .value.toUpperCase();
        operatorTest();
        pseudoSwitchId(opeTest);
        pseudoSwitchColId(row);
        updateNum();
        break;
      case "DATE":
        operatorDate();
        const opeDate = document
          .getElementById("Dateoperator")
          .value.toUpperCase();
        pseudoSwitchDate(opeDate);
        updateNum();
        break;
      case "STATUS":
        operatorStatus();
        const opeStatus = document
          .getElementById("Soperator")
          .value.toUpperCase();
        pseudoSwitchStatus(opeStatus);
        updateNum();
        break;
      case "RESULT":
        operatorResult();
        const opeResult = document
          .getElementById("Roperator")
          .value.toUpperCase();
        pseudoSwitchResult(opeResult);
        updateNum();
        break;
      default:
        operator();
        const ope = document.getElementById("operator").value.toUpperCase();
        pseudoSwitch(ope);
        pseudoSwitchCol(row);
        updateNum();
        break;
    }
    const filters = $("input.filter").get();
  });
  $("#column").change(function () {
    var row = $(this).val().toUpperCase();
    $("#operators, #Idoperators, #Dateoperators, #filter, #filterId, #filterDate, #DateContext, #filterYear, #Soperators, #Roperators, #SContexts, #RContexts").hide();
    if (row == "DATE") {
      $("#Dateoperators, #DateContext").show();
    } else if (row == "ID" || row == "TESTS") {
      $("#Idoperators, #filterId").show();
    } else if (row == "RESULT") {
      $("#Roperators, #RContexts").show();
    } else if (row == "STATUS") {
      $("#Soperators, #SContexts").show();
    } else {
      $("#operators, #filter").show();
    }
  });
  $("#Dateoperator").change(function () {
    var row = $(this).val().toUpperCase();
    if (row == "OPEI" || row == "OPEIN") {
      $("#DateContext").show();
      $("#filterDate, #filterYear").hide();
    } else {
      $("#DateContext").hide();
      $("#filterDate").show();
      $("#filterYear").hide();
    }
  });
  $("#DateContext").change(function () {
    var row = $(this).val().toUpperCase();
    if (row == "EXADA") {
      $("#filterDate").show();
      $("#filterYear").hide();
    } else if (row == "YEAR") {
      $("#filterDate").hide();
      $("#filterYear").show();
    } else {
      $("#filterDate, #filterYear").hide();
    }
  });
})(jQuery);