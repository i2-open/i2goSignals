import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Radio, TrendingUp, CheckCircle, AlertTriangle } from 'lucide-react';
import type { Stream, EventTransmission, Receiver } from '../types';

interface DashboardProps {
  streams: Stream[];
  transmissions: EventTransmission[];
  receivers: Receiver[];
}

export function Dashboard({ streams, transmissions, receivers }: DashboardProps) {
  const activeStreams = streams.filter(s => s.status === 'enabled').length;
  const totalEvents = streams.reduce((sum, s) => sum + s.eventsDelivered, 0);
  const totalErrors = streams.reduce((sum, s) => sum + s.errors, 0);
  const successRate = transmissions.length > 0
    ? ((transmissions.filter(t => t.status === 'delivered').length / transmissions.length) * 100).toFixed(1)
    : '0';

  return (
    <div className="space-y-8">
      <div>
        <h1 className="mb-2">Dashboard</h1>
        <p className="text-muted-foreground">OpenID Shared Signals Framework - Event Stream Overview</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm">Active Streams</CardTitle>
            <Radio className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl">{activeStreams} / {streams.length}</div>
            <p className="text-xs text-muted-foreground">Currently enabled</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm">Events Delivered</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl">{totalEvents.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground">All time</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm">Success Rate</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl">{successRate}%</div>
            <p className="text-xs text-muted-foreground">Delivery success</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm">Errors</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl">{totalErrors}</div>
            <p className="text-xs text-muted-foreground">Failed deliveries</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Active Streams</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {streams.map((stream) => (
                <div key={stream.id} className="flex items-center justify-between border-b pb-3 last:border-0">
                  <div className="space-y-1">
                    <p className="text-sm font-mono">{stream.configuration.iss}</p>
                    <p className="text-xs text-muted-foreground">
                      {stream.eventsDelivered.toLocaleString()} events
                    </p>
                  </div>
                  <Badge variant={stream.status === 'enabled' ? 'default' : 'secondary'}>
                    {stream.status}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent Transmissions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {transmissions.slice(0, 5).map((t) => {
                const eventType = Object.keys(t.set.events)[0];
                const eventName = eventType.split('/').pop()?.replace(/-/g, ' ') || 'Unknown';
                return (
                  <div key={t.id} className="flex items-center justify-between border-b pb-3 last:border-0">
                    <div className="space-y-1">
                      <p className="text-sm capitalize">{eventName}</p>
                      <p className="text-xs text-muted-foreground font-mono">
                        {t.set.jti.substring(0, 16)}...
                      </p>
                    </div>
                    <Badge variant={t.status === 'delivered' ? 'default' : t.status === 'failed' ? 'destructive' : 'secondary'}>
                      {t.status}
                    </Badge>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
