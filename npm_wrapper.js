#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const VENV_DIR = path.join(__dirname, 'venv-cascavel');
const CASCAVEL_SCRIPT = path.join(__dirname, 'cascavel.py');

console.log("\x1b[36m[Cascavel-CTEM]\x1b[0m Bootstrapping Enterprise Python Environment...");

try {
    // Check if python3 is available
    execSync('python3 --version', { stdio: 'ignore' });

    // Ensure venv exists
    if (!fs.existsSync(VENV_DIR)) {
        console.log("\x1b[33m[Cascavel-CTEM]\x1b[0m Creating isolated virtual environment...");
        execSync(`python3 -m venv ${VENV_DIR}`);
        execSync(`${path.join(VENV_DIR, 'bin', 'pip')} install -r ${path.join(__dirname, 'requirements.txt')} --quiet`);
    }

    // Run Cascavel
    const pythonExecutable = path.join(VENV_DIR, 'bin', 'python');
    const args = process.argv.slice(2).join(' ');
    execSync(`${pythonExecutable} ${CASCAVEL_SCRIPT} ${args}`, { stdio: 'inherit' });

} catch (error) {
    console.error("\x1b[31m[Cascavel-CTEM Error]\x1b[0m Failed to execute Cascavel.");
    console.error("Please ensure Python 3.10+ is installed on your system.");
    process.exit(1);
}
