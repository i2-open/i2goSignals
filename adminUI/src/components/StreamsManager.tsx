import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Plus } from 'lucide-react';
import type { Stream } from '../types';

interface StreamsManagerProps {
  streams: Stream[];
  setStreams: (streams: Stream[]) => void;
}

export function StreamsManager({ streams, setStreams }: StreamsManagerProps) {
  const toggleStatus = (streamId: string) => {
    setStreams(streams.map(s => 
      s.id === streamId 
        ? { ...s, status: s.status === 'enabled' ? 'paused' : 'enabled' as const }
        : s
    ));
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="mb-2">Streams</h1>
          <p className="text-muted-foreground">Manage event stream configurations</p>
        </div>
        <Button>
          <Plus className="h-4 w-4 mr-2" />
          New Stream
        </Button>
      </div>

      <div className="grid gap-4">
        {streams.map((stream) => (
          <Card key={stream.id}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-base font-mono">{stream.configuration.iss}</CardTitle>
                <div className="flex items-center gap-2">
                  <Badge variant={stream.status === 'enabled' ? 'default' : 'secondary'}>
                    {stream.status}
                  </Badge>
                  <Button variant="outline" size="sm" onClick={() => toggleStatus(stream.id)}>
                    {stream.status === 'enabled' ? 'Pause' : 'Enable'}
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <p className="text-muted-foreground">Method</p>
                  <p>{stream.configuration.delivery.method === 'urn:ietf:rfc:8935' ? 'Push' : 'Poll'}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Events Delivered</p>
                  <p>{stream.eventsDelivered.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Errors</p>
                  <p>{stream.errors}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Event Types</p>
                  <p>{stream.configuration.events_supported.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
