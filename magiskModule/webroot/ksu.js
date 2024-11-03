let callbackCounter = 0;
function getUniqueCallbackName(prefix) {
  return `${prefix}_callback_${Date.now()}_${callbackCounter++}`;
}

export function exec(command, options) {
  if (typeof options === "undefined") {
    options = {};
  }

  return new Promise((resolve, reject) => {
    // Generate a unique callback function name
    const callbackFuncName = getUniqueCallbackName("exec");

    // Define the success callback function
    window[callbackFuncName] = (errno, stdout, stderr) => {
      resolve({ errno, stdout, stderr });
      cleanup(callbackFuncName);
    };

    function cleanup(successName) {
      delete window[successName];
    }

    try {
      ksu.exec(command, JSON.stringify(options), callbackFuncName);
    } catch (error) {
      reject(error);
      cleanup(callbackFuncName);
    }
  });
}

function Stdio() {
    this.listeners = {};
  }
  
  Stdio.prototype.on = function (event, listener) {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(listener);
  };
  
  Stdio.prototype.emit = function (event, ...args) {
    if (this.listeners[event]) {
      this.listeners[event].forEach((listener) => listener(...args));
    }
  };
  
  function ChildProcess() {
    this.listeners = {};
    this.stdin = new Stdio();
    this.stdout = new Stdio();
    this.stderr = new Stdio();
  }
  
  ChildProcess.prototype.on = function (event, listener) {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(listener);
  };
  
  ChildProcess.prototype.emit = function (event, ...args) {
    if (this.listeners[event]) {
      this.listeners[event].forEach((listener) => listener(...args));
    }
  };
  
  export function spawn(command, args, options) {
    if (typeof args === "undefined") {
      args = [];
    } else if (typeof args === "object") {
        // allow for (command, options) signature
        options = args;
    }
    
    if (typeof options === "undefined") {
      options = {};
    }
  
    const child = new ChildProcess();
    const childCallbackName = getUniqueCallbackName("spawn");
    window[childCallbackName] = child;
  
    function cleanup(name) {
      delete window[name];
    }

    child.on("exit", code => {
        cleanup(childCallbackName);
    });

    try {
      ksu.spawn(
        command,
        JSON.stringify(args),
        JSON.stringify(options),
        childCallbackName
      );
    } catch (error) {
      child.emit("error", error);
      cleanup(childCallbackName);
    }
    return child;
  }

export function fullScreen(isFullScreen) {
  ksu.fullScreen(isFullScreen);
}

export function toast(message) {
  ksu.toast(message);
}

export function readFile(filePath) {
    return exec(`cat ${filePath}`).then(result => {
        if (result.errno === 0) {
            return result.stdout;
        } else {
            throw new Error(`Error reading file: ${result.stderr}`);
        }
    });
}

export function writeFile(filePath, content) {
    return exec(`echo "${content.replace(/\n/g, '\\n')}" > ${filePath}`).then(result => {
        if (result.errno === 0) {
            return;
        } else {
            throw new Error(`Error writing file: ${result.stderr}`);
        }
    });
}

export function moduleInfo() {
    return new Promise((resolve, reject) => {
        const callbackFuncName = getUniqueCallbackName("moduleInfo");

        window[callbackFuncName] = (info) => {
            resolve(info);
            cleanup(callbackFuncName);
        };

        function cleanup(name) {
            delete window[name];
        }

        try {
            ksu.moduleInfo(callbackFuncName);
        } catch (error) {
            reject(error);
            cleanup(callbackFuncName);
        }
    });
}