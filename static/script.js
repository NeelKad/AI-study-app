document.addEventListener('DOMContentLoaded', () => {
  const mainContent = document.getElementById('mainContent');
  if (!mainContent || window.location.pathname !== '/flashcards') return;

  async function loadFlashcards() {
    const notes = sessionStorage.getItem('processedNotes');
    if (!notes) {
      alert('No processed notes found! Please enter and process notes first.');
      window.location.href = '/';
      return;
    }

    mainContent.innerHTML = '<p>Loading flashcards...</p>';

    try {
      const res = await fetch('/api/flashcards', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notes }),
      });
      if (!res.ok) throw new Error('Failed to fetch flashcards.');
      const data = await res.json();

      if (Object.keys(data).length === 0) {
        mainContent.innerHTML = '<p>No flashcards generated.</p>';
        return;
      }

      renderFlashcards(data);
    } catch (err) {
      mainContent.innerHTML = `<p style="color:red;">${err.message}</p>`;
    }
  }

  function renderFlashcards(data) {
    const flashcards = Object.entries(data).map(([term, definition]) => ({
      term,
      definition,
    }));

    let currentIndex = 0;
    let showingDefinition = false;

    // Clear mainContent and add the flashcard container and buttons
    mainContent.innerHTML = `
      <div id="flashcard" style="
        max-width: 600px;
        margin: 60px auto 20px;
        padding: 40px 20px;
        font-size: 28px;
        border: 2px solid #333;
        border-radius: 12px;
        text-align: center;
        cursor: pointer;
        user-select: none;
        background: #f9f9f9;
        box-shadow: 0 4px 10px rgba(0,0,0,0.1);
      "></div>
      <div style="text-align:center;">
        <button id="prevBtn" style="margin-right: 20px; padding: 10px 20px; font-size:16px;">← Previous</button>
        <button id="nextBtn" style="padding: 10px 20px; font-size:16px;">Next →</button>
      </div>
    `;

    const flashcardDiv = document.getElementById('flashcard');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');

    function updateFlashcard() {
      const card = flashcards[currentIndex];
      flashcardDiv.textContent = showingDefinition ? card.definition : card.term;
      prevBtn.disabled = currentIndex === 0;
      nextBtn.disabled = currentIndex === flashcards.length - 1;
    }

    flashcardDiv.addEventListener('click', () => {
      showingDefinition = !showingDefinition;
      updateFlashcard();
    });

    prevBtn.addEventListener('click', () => {
      if (currentIndex > 0) {
        currentIndex--;
        showingDefinition = false;
        updateFlashcard();
      }
    });

    nextBtn.addEventListener('click', () => {
      if (currentIndex < flashcards.length - 1) {
        currentIndex++;
        showingDefinition = false;
        updateFlashcard();
      }
    });

    updateFlashcard();
  }

  loadFlashcards();
});
