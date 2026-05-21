import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Shell from './components/layout/Shell';
import Overview from './pages/Overview';
import Logs from './pages/Logs';
import UnauthorizedAccess from './pages/UnauthorizedAccess';
import S3Buckets from './pages/S3Buckets';
import IamMisuse from './pages/IamMisuse';
import Settings from './pages/Settings';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Shell />}>
          <Route index element={<Overview />} />
          <Route path="logs" element={<Logs />} />
          <Route path="access" element={<UnauthorizedAccess />} />
          <Route path="s3" element={<S3Buckets />} />
          <Route path="iam" element={<IamMisuse />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<Overview />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
};

export default App;
