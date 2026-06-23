import { useState } from 'react';

export default function Hello() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <h1>Hello from Clarisys</h1>
      <p style={{ marginTop: '1rem', color: '#64748b' }}>
        React + Astro is working.
      </p>
      <button
        onClick={() => setCount(count + 1)}
        style={{
          marginTop: '1.5rem',
          padding: '0.5rem 1.5rem',
          borderRadius: '0.375rem',
          border: '1px solid #e2e8f0',
          background: '#fff',
          cursor: 'pointer',
          fontSize: '1rem',
        }}
      >
        Count: {count}
      </button>
    </div>
  );
}
