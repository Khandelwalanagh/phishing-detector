/* ============================================================
   PhishGuard — Gmail Chat Integration
   Injects a chat widget into Gmail and reads the active email.
   ============================================================ */

   const API_ENDPOINT = 'http://localhost:8000/api/chat';

   let chatHistory = [];
   let widgetOpen = false;
   
   // ── Inject UI ──────────────────────────────────────────────
   function injectWidget() {
     if (document.getElementById('__pg_chat_widget')) return;
   
     const container = document.createElement('div');
     container.id = '__pg_chat_widget';
   
     container.innerHTML = `
       <div id="__pg_chat_window">
         <div id="__pg_chat_header">
           <div id="__pg_chat_title">
             <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#6c63ff" stroke-width="2">
               <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
             </svg>
             PhishGuard AI
           </div>
           <button id="__pg_chat_close">
             <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
               <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
             </svg>
           </button>
         </div>
         <div id="__pg_chat_messages">
           <div class="pg-message assistant">
             Hi! I'm PhishGuard AI. Open an email, and I can help you figure out if it's safe or suspicious.
           </div>
         </div>
         <div id="__pg_chat_input_area">
           <input type="text" id="__pg_chat_input" placeholder="Ask about this email..." autocomplete="off">
           <button id="__pg_chat_send">
             <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
               <path stroke-linecap="round" stroke-linejoin="round" d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z" />
             </svg>
           </button>
         </div>
       </div>
       <button id="__pg_chat_button" title="Chat with PhishGuard AI">
         <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
           <path stroke-linecap="round" stroke-linejoin="round" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
         </svg>
       </button>
     `;
   
     document.body.appendChild(container);
   
     // Event Listeners
     document.getElementById('__pg_chat_button').addEventListener('click', toggleWidget);
     document.getElementById('__pg_chat_close').addEventListener('click', toggleWidget);
     
     const input = document.getElementById('__pg_chat_input');
     const sendBtn = document.getElementById('__pg_chat_send');
   
     // Send on Enter
     input.addEventListener('keypress', (e) => {
       if (e.key === 'Enter') handleSend();
     });
     sendBtn.addEventListener('click', handleSend);
   }
   
   // ── Logic ──────────────────────────────────────────────────
   
   function toggleWidget() {
     const win = document.getElementById('__pg_chat_window');
     widgetOpen = !widgetOpen;
     if (widgetOpen) {
       win.classList.add('open');
       document.getElementById('__pg_chat_input').focus();
     } else {
       win.classList.remove('open');
     }
   }
   
   // Extract the current email body from Gmail's DOM
   function getEmailContext() {
     // Gmail often puts the currently open email body in a container with class '.a3s.aiL'
     // We look for all of them, but usually the last visible one is the current email in a thread.
     const emailBodies = document.querySelectorAll('.a3s.aiL');
     if (!emailBodies || emailBodies.length === 0) return "";
     
     // Get the text from the last one (most recent in the thread view usually)
     const activeBody = emailBodies[emailBodies.length - 1];
     return activeBody.innerText || activeBody.textContent;
   }
   
   function appendMessage(role, text) {
     const messagesDiv = document.getElementById('__pg_chat_messages');
     const msgEl = document.createElement('div');
     msgEl.className = `pg-message ${role}`;
     msgEl.textContent = text;
     messagesDiv.appendChild(msgEl);
     messagesDiv.scrollTop = messagesDiv.scrollHeight;
   }
   
   function showLoading() {
     const messagesDiv = document.getElementById('__pg_chat_messages');
     const msgEl = document.createElement('div');
     msgEl.id = '__pg_loading';
     msgEl.className = `pg-message assistant pg-loading-dots`;
     msgEl.innerHTML = `<span></span><span></span><span></span>`;
     messagesDiv.appendChild(msgEl);
     messagesDiv.scrollTop = messagesDiv.scrollHeight;
   }
   
   function hideLoading() {
     const loadingEl = document.getElementById('__pg_loading');
     if (loadingEl) loadingEl.remove();
   }
   
   async function handleSend() {
     const input = document.getElementById('__pg_chat_input');
     const sendBtn = document.getElementById('__pg_chat_send');
     const message = input.value.trim();
   
     if (!message) return;
   
     // UI Updates
     input.value = '';
     input.disabled = true;
     sendBtn.disabled = true;
   
     appendMessage('user', message);
     showLoading();
   
     const emailContext = getEmailContext();
   
     try {
       const res = await fetch(API_ENDPOINT, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({
           message: message,
           email_context: emailContext,
           history: chatHistory
         })
       });
   
       if (!res.ok) throw new Error('API Error');
   
       const data = await res.json();
       const aiResponse = data.response;
   
       hideLoading();
       appendMessage('assistant', aiResponse);
   
       // Update history
       chatHistory.push({ role: 'user', content: message });
       chatHistory.push({ role: 'assistant', content: aiResponse });
   
     } catch (err) {
       hideLoading();
       appendMessage('assistant', "I'm sorry, I couldn't reach the backend server. Is it running on port 8000?");
     } finally {
       input.disabled = false;
       sendBtn.disabled = false;
       input.focus();
     }
   }
   
   // Inject after a short delay to ensure Gmail has loaded
   setTimeout(injectWidget, 2000);
   
