// Scroll Reveal
const reveals = document.querySelectorAll('.reveal');
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });
reveals.forEach(el => observer.observe(el));

// Nav scroll effect
const navbar = document.getElementById('navbar');
let scrollTicking = false;
window.addEventListener('scroll', () => {
  if (!scrollTicking) {
    window.requestAnimationFrame(() => {
      navbar.classList.toggle('scrolled', window.scrollY > 50);
      const btn = document.getElementById('backToTop');
      btn.classList.toggle('visible', window.scrollY > 600);
      scrollTicking = false;
    });
    scrollTicking = true;
  }
}, { passive: true });

// Back to top
document.getElementById('backToTop').addEventListener('click', () => {
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

// 3D Tilt Effect for Premium UX
const cardsElements = document.querySelectorAll('.feature-card, .roadmap-card, .intel-card, .arch-item');
cardsElements.forEach(el => {
  el.addEventListener('mousemove', e => {
    const rect = el.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    el.style.setProperty('--mouse-x', `${x}px`);
    el.style.setProperty('--mouse-y', `${y}px`);

    if (window.innerWidth > 768) {
      const centerX = rect.width / 2;
      const centerY = rect.height / 2;
      const rotateX = ((y - centerY) / centerY) * -8;
      const rotateY = ((x - centerX) / centerX) * 8;
      el.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.02, 1.02, 1.02)`;
      el.style.zIndex = 10;
    }
  });
  el.addEventListener('mouseleave', () => {
    el.style.transform = '';
    el.style.zIndex = 1;
  });
});

// Active nav link (desktop + mobile bottom pill) using IntersectionObserver
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.nav-links a[href^="#"]');
const bottomLinks = document.querySelectorAll('#bottomNav a[href^="#"]');

const sectionObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const current = entry.target.getAttribute('id');
      navLinks.forEach(link => {
        link.style.color = link.getAttribute('href') === '#' + current ? 'var(--cyan)' : '';
      });
      bottomLinks.forEach(l => {
        l.classList.toggle('active', l.getAttribute('href') === '#' + current);
      });
    }
  });
}, { rootMargin: '-120px 0px -50% 0px', threshold: 0 });

sections.forEach(section => sectionObserver.observe(section));

// Advanced 3D Cyber Canvas Background (Warp Tunnel & Quantum Dust)
const canvas = document.getElementById('particles-bg');
const ctx = canvas.getContext('2d');
let width, height, cx, cy;
let time = 0;

let stars = [];
const focalLength = 500;

let lastWidth = window.innerWidth;
function resize() {
  // Prevent canvas resize on mobile when only height changes (address bar show/hide during scroll)
  if (window.innerWidth <= 768 && window.innerWidth === lastWidth) return;
  if (window.innerWidth === canvas.width && window.innerHeight === canvas.height) return;

  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  width = canvas.width;
  height = canvas.height;
  cx = width / 2;
  cy = height / 2;
  lastWidth = window.innerWidth;
  initStars();
}

let resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(resize, 250);
});

// Initial size setup
resize();

class Star {
  constructor() {
    this.reset();
    this.z = Math.random() * 2000; // Start at random depths
  }
  reset() {
    this.x = (Math.random() - 0.5) * 4000;
    this.y = (Math.random() - 0.5) * 4000;
    this.z = 2000;
    this.speed = Math.random() * 3 + 1.5;
    this.color = Math.random() > 0.6 ? 'rgba(255, 45, 149,' : 'rgba(0, 255, 229,';
    this.glow = Math.random() * 2 + 0.5;
  }
  update() {
    this.z -= this.speed;
    if (this.z <= 0) this.reset();
  }
  draw() {
    let scale = focalLength / this.z;
    let px = cx + this.x * scale;
    let py = cy + this.y * scale;
    let size = Math.max(0.1, this.glow * scale);
    let opacity = Math.min(1, 1 - (this.z / 2000));

    if (px >= 0 && px <= width && py >= 0 && py <= height && opacity > 0) {
      ctx.beginPath();
      ctx.arc(px, py, size, 0, Math.PI * 2);
      ctx.fillStyle = this.color + opacity + ')';
      ctx.fill();
    }
  }
}

function initStars() {
  stars = [];
  const numStars = Math.min(Math.floor(window.innerWidth / 15), 100); // Scaled down for mobile performance
  for (let i = 0; i < numStars; i++) stars.push(new Star());
}

function drawPerspectiveGrid() {
  let gridY = (time * 40) % 200;
  ctx.lineWidth = 1;

  // Horizontal Floor & Ceiling Lines
  ctx.beginPath();
  for (let i = 1; i < 20; i++) {
    let z = i * 150 - gridY;
    if (z <= 0) continue;
    let scale = focalLength / z;
    let pyFloor = cy + 400 * scale;
    let pyCeiling = cy - 400 * scale;
    let opacity = Math.max(0, 1 - (z / 2000));

    ctx.strokeStyle = `rgba(0, 255, 229, ${opacity * 0.15})`;

    if (pyFloor > cy && pyFloor < height * 1.5) {
      ctx.moveTo(0, pyFloor); ctx.lineTo(width, pyFloor);
    }
    if (pyCeiling < cy && pyCeiling > -height * 0.5) {
      ctx.moveTo(0, pyCeiling); ctx.lineTo(width, pyCeiling);
    }
  }
  ctx.stroke();

  // Vertical Perspective Lines
  ctx.beginPath();
  ctx.strokeStyle = 'rgba(0, 255, 229, 0.1)';
  for (let i = -15; i <= 15; i++) {
    let x = i * 200;
    let pxFar = cx + x * (focalLength / 2000);
    let pyFarFloor = cy + 400 * (focalLength / 2000);
    let pyFarCeil = cy - 400 * (focalLength / 2000);

    let pxNear = cx + x * (focalLength / 50);
    let pyNearFloor = cy + 400 * (focalLength / 50);
    let pyNearCeil = cy - 400 * (focalLength / 50);

    // Floor
    ctx.moveTo(pxFar, pyFarFloor); ctx.lineTo(pxNear, pyNearFloor);
    // Ceiling
    ctx.moveTo(pxFar, pyFarCeil); ctx.lineTo(pxNear, pyNearCeil);
  }
  ctx.stroke();
}

let isCanvasVisible = true;

function animateCanvas() {
  if (!isCanvasVisible) return;
  time += 0.016;
  ctx.clearRect(0, 0, width, height);

  // Ambient core glow
  const gradCore = ctx.createRadialGradient(cx, cy, 0, cx, cy, width * 0.5);
  gradCore.addColorStop(0, 'rgba(0, 255, 229, 0.05)');
  gradCore.addColorStop(1, 'transparent');
  ctx.fillStyle = gradCore;
  ctx.fillRect(0, 0, width, height);

  drawPerspectiveGrid();

  for (let i = 0; i < stars.length; i++) {
    stars[i].update();
    stars[i].draw();
  }

  requestAnimationFrame(animateCanvas);
}

// Pause animation when scrolled out of view
const canvasObserver = new IntersectionObserver((entries) => {
  isCanvasVisible = entries[0].isIntersecting;
  if (isCanvasVisible) requestAnimationFrame(animateCanvas);
}, { threshold: 0 });
canvasObserver.observe(document.querySelector('.hero'));

// Stats Counter Animation
const statsSection = document.getElementById('stats-section');
const counters = document.querySelectorAll('.stat-number');
let countersStarted = false;

if (statsSection) {
  counters.forEach(counter => {
    const text = counter.innerText;
    const target = parseFloat(text);
    const suffix = text.replace(/[0-9.]/g, '');
    counter.setAttribute('data-target', target);
    counter.setAttribute('data-suffix', suffix);
    counter.innerText = '0' + suffix;
  });

  const runCounters = () => {
    counters.forEach(counter => {
      const target = parseFloat(counter.getAttribute('data-target'));
      const suffix = counter.getAttribute('data-suffix') || '';
      const duration = 2000;
      const stepTime = 20;
      const steps = duration / stepTime;
      const increment = target / steps;
      let current = 0;

      const updateCounter = setInterval(() => {
        current += increment;
        if (current >= target) {
          counter.innerText = (Number.isInteger(target) ? target : target.toFixed(1)) + suffix;
          clearInterval(updateCounter);
        } else {
          counter.innerText = (Number.isInteger(target) ? Math.floor(current) : current.toFixed(1)) + suffix;
        }
      }, stepTime);
    });
  };

  const statsObserver = new IntersectionObserver(entries => {
    if (entries[0].isIntersecting && !countersStarted) {
      countersStarted = true;
      runCounters();
    }
  }, { threshold: 0.5 });
  statsObserver.observe(statsSection);
}

// Terminal Typewriter Animation
const terminalBody = document.getElementById('terminal-body');
if (terminalBody) {
  const commands = [];
  Array.from(terminalBody.children).forEach(el => {
    if (el.classList.contains('comment')) commands.push({ type: 'comment', text: el.innerText });
    else if (el.classList.contains('cmd')) commands.push({ type: 'cmd', text: el.innerText });
  });

  terminalBody.innerHTML = '<span class="cursor" id="cursor"></span>';

  let cmdIndex = 0;
  let charIndex = 0;

  function typeCommand() {
    if (cmdIndex >= commands.length) return;

    const cmd = commands[cmdIndex];
    const cursor = document.getElementById('cursor');

    if (charIndex === 0) {
      if (cmd.type === 'comment') {
        const span = document.createElement('span');
        span.className = 'comment';
        terminalBody.insertBefore(span, cursor);
      } else {
        const prompt = document.createElement('span');
        prompt.className = 'prompt';
        prompt.innerText = '❯ ';
        terminalBody.insertBefore(prompt, cursor);

        const span = document.createElement('span');
        span.className = 'cmd';
        terminalBody.insertBefore(span, cursor);
      }
    }

    const currentElement = cursor.previousElementSibling;

    if (charIndex < cmd.text.length) {
      currentElement.textContent += cmd.text.charAt(charIndex);
      charIndex++;
      setTimeout(typeCommand, cmd.type === 'comment' ? 15 : 40);
    } else {
      const br = document.createElement('br');
      terminalBody.insertBefore(br, cursor);
      cmdIndex++;
      charIndex = 0;
      setTimeout(typeCommand, 400);
    }
  }

  const terminalObserver = new IntersectionObserver(entries => {
    if (entries[0].isIntersecting) {
      setTimeout(typeCommand, 500);
      terminalObserver.disconnect();
    }
  }, { threshold: 0.5 });
  terminalObserver.observe(terminalBody);
}
