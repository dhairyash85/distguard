import { Routes, Route } from 'react-router-dom';
import Home from './pages/Home';
import Stats from './pages/Stats';
import ZKPVerify from './pages/ZKPVerify';

function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/stats" element={<Stats />} />
      <Route path="/zkp" element={<ZKPVerify />} />
    </Routes>
  );
}

export default App;
