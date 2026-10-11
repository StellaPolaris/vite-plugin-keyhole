import './style.css';
import logo from './logo.svg';

const app = document.getElementById('app');
app.innerHTML = `<h1>KEYHOLE-CANARY-7f3a9c</h1><img alt="logo" src="${logo}">`;
// Dynamic imports must be inlined into the single chunk too.
import('./lazy.js').then((m) => app.append(m.text));
