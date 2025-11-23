import { useState } from 'react';
import { Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent, SidebarGroupLabel, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider } from './components/ui/sidebar';
import { Activity, Radio, FileText, Send, Inbox, Settings } from 'lucide-react';
import { Dashboard } from './components/Dashboard';
import { StreamsManager } from './components/StreamsManager';
import { EventTypesManager } from './components/EventTypesManager';
import { TransmittersManager } from './components/TransmittersManager';
import { ReceiversManager } from './components/ReceiversManager';
import { mockStreams, mockEventFamilies, mockTransmitters, mockReceivers, mockEventTransmissions } from './lib/mock-data';
import type { Stream, EventFamily, Transmitter, Receiver } from './types';
import goSignalsImg from './assets/GoSignals-msgs.svg';
import { UserMenu } from './components/UserMenu';

type View = 'dashboard' | 'streams' | 'events' | 'transmitters' | 'receivers' | 'settings';

export default function App() {
  const [view, setView] = useState<View>('dashboard');
  const [streams, setStreams] = useState<Stream[]>(mockStreams);
  const [eventFamilies, setEventFamilies] = useState<EventFamily[]>(mockEventFamilies);
  const [transmitters, setTransmitters] = useState<Transmitter[]>(mockTransmitters);
  const [receivers, setReceivers] = useState<Receiver[]>(mockReceivers);

  const navigation = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'streams', label: 'Streams', icon: Radio },
    { id: 'events', label: 'Event Types', icon: FileText },
    { id: 'transmitters', label: 'Transmitters', icon: Send },
    { id: 'receivers', label: 'Receivers', icon: Inbox },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  const renderView = () => {
    switch (view) {
      case 'dashboard':
        return <Dashboard streams={streams} transmissions={mockEventTransmissions} receivers={receivers} />;
      case 'streams':
        return <StreamsManager streams={streams} setStreams={setStreams} />;
      case 'events':
        return <EventTypesManager eventFamilies={eventFamilies} setEventFamilies={setEventFamilies} />;
      case 'transmitters':
        return <TransmittersManager transmitters={transmitters} setTransmitters={setTransmitters} />;
      case 'receivers':
        return <ReceiversManager receivers={receivers} setReceivers={setReceivers} />;
      case 'settings':
        return (
          <div className="space-y-6">
            <div>
              <h2 className="mb-2">Configuration</h2>
              <p className="text-muted-foreground">System configuration and settings</p>
            </div>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <SidebarProvider>
      <div className="flex min-h-screen w-full">
        <Sidebar>
          <SidebarContent>
            <div className="p-6 border-b">
                <a href="https://i2gosignals.io"><img src={goSignalsImg} alt="GoSignals" width="140px"/></a>
              <h1 className="text-xl">I2 GoSignals</h1>
              <p className="text-sm text-muted-foreground">SSF Event Router v0.1</p>
            </div>
            <SidebarGroup>
              <SidebarGroupLabel>Management</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {navigation.map((item) => (
                    <SidebarMenuItem key={item.id}>
                      <SidebarMenuButton
                        isActive={view === item.id}
                        onClick={() => setView(item.id as View)}
                      >
                        <item.icon className="h-4 w-4" />
                        <span>{item.label}</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </SidebarContent>
        </Sidebar>
        <div className="flex-1 flex flex-col">
          <header className="w-full border-b px-8 py-4 flex items-center justify-between">
            <div className="text-sm text-muted-foreground">
              {new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
            </div>
            <UserMenu />
          </header>
          <main className="flex-1 p-8">
            {renderView()}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
