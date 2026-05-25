import React from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import EventDrawer from '../shared/EventDrawer';

export const Shell: React.FC = () => {
  return (
    <div className="min-h-screen flex bg-[#F8FAFC] dark:bg-[#090D16] text-gray-900 dark:text-gray-100 transition-colors duration-250">
      
      {/* Navigation Sidebar */}
      <Sidebar />
      
      {/* Main Workspace Frame */}
      {/* Pl-0 on mobile, Pl-[220px] on desktop. pb-14 on mobile (nav bar height), pb-0 on desktop */}
      <div className="flex-1 flex flex-col md:pl-[220px] pb-14 md:pb-0 min-h-screen overflow-x-hidden">
        
        {/* Top Header Controls */}
        <TopBar />
        
        {/* Scrollable Content (14px padding) */}
        <main className="flex-1 p-[14px] overflow-y-auto relative">
          <Outlet />
        </main>
        
      </div>

      {/* Global Event Slide-out Inspector */}
      <EventDrawer />
      
    </div>
  );
};

export default Shell;
