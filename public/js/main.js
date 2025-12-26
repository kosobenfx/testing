document.addEventListener('DOMContentLoaded', () => {
  // Simple client-side enhancement: fade in cards
  document.querySelectorAll('.card').forEach((card) => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(8px)';
    requestAnimationFrame(() => {
      card.style.transition = 'opacity 250ms ease-out, transform 250ms ease-out';
      card.style.opacity = '1';
      card.style.transform = 'translateY(0)';
    });
  });
});


