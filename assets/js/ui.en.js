// Scroll Reveal
const reveals=document.querySelectorAll('.reveal');
const observer=new IntersectionObserver(e=>{e.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.add('visible');observer.unobserve(entry.target)}})},{threshold:.1,rootMargin:'0px 0px -50px 0px'});
reveals.forEach(el=>observer.observe(el));

// Nav scroll + back to top
const navbar=document.getElementById('navbar');
window.addEventListener('scroll',()=>{
  navbar.classList.toggle('scrolled',window.scrollY>50);
  document.getElementById('backToTop').classList.toggle('visible',window.scrollY>600);
},{passive:true});
document.getElementById('backToTop').addEventListener('click',()=>{window.scrollTo({top:0,behavior:'smooth'})});

// Active nav (bottom pill)
const sections=document.querySelectorAll('section[id]');
const bottomLinks=document.querySelectorAll('#bottomNav a[href^="#"]');
window.addEventListener('scroll',()=>{
  let current='';
  sections.forEach(s=>{if(scrollY>=s.offsetTop-120)current=s.getAttribute('id')});
  bottomLinks.forEach(l=>{l.classList.toggle('active',l.getAttribute('href')==='#'+current)});
},{passive:true});

// Particles Background Animation
const canvas = document.getElementById('particles-bg');
const ctx = canvas.getContext('2d');
let particles = [];

function resize() {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
}
window.addEventListener('resize', resize);
resize();

class Particle {
  constructor() {
    this.x = Math.random() * canvas.width;
    this.y = Math.random() * canvas.height;
    this.vx = (Math.random() - 0.5) * 0.4;
    this.vy = (Math.random() - 0.5) * 0.4;
    this.radius = Math.random() * 1.5 + 0.5;
  }
  update() {
    this.x += this.vx;
    this.y += this.vy;
    if (this.x < 0 || this.x > canvas.width) this.vx = -this.vx;
    if (this.y < 0 || this.y > canvas.height) this.vy = -this.vy;
  }
  draw() {
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(0, 255, 229, 0.5)';
    ctx.fill();
  }
}

function initParticles() {
  particles = [];
  const numParticles = Math.min(Math.floor(window.innerWidth / 18), 80);
  for (let i = 0; i < numParticles; i++) particles.push(new Particle());
}

function animateParticles() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  for (let i = 0; i < particles.length; i++) {
    particles[i].update();
    particles[i].draw();
    for (let j = i + 1; j < particles.length; j++) {
      const dx = particles[i].x - particles[j].x;
      const dy = particles[i].y - particles[j].y;
      const dist = dx * dx + dy * dy;
      if (dist < 12000) {
        ctx.beginPath();
        ctx.strokeStyle = `rgba(0, 255, 229, ${0.15 - dist / 80000})`;
        ctx.lineWidth = 0.6;
        ctx.moveTo(particles[i].x, particles[i].y);
        ctx.lineTo(particles[j].x, particles[j].y);
        ctx.stroke();
      }
    }
  }
  requestAnimationFrame(animateParticles);
}
initParticles();
animateParticles();

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

// Card Glow Effect (Premium UI)
const cards = document.querySelectorAll('.feature-card, .roadmap-card, .intel-card, .arch-item');
cards.forEach(card => {
  card.addEventListener('mousemove', e => {
    const rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    card.style.setProperty('--mouse-x', `${x}px`);
    card.style.setProperty('--mouse-y', `${y}px`);
  });
});

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
