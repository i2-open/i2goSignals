import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { RefreshCw } from 'lucide-react';
import type { Transmitter } from '../types';

interface TransmittersManagerProps {
  transmitters: Transmitter[];
  setTransmitters: (transmitters: Transmitter[]) => void;
}

export function TransmittersManager({ transmitters, setTransmitters }: TransmittersManagerProps) {
  const syncTransmitter = (id: string) => {
    setTransmitters(transmitters.map(t =>
      t.id === id ? { ...t, lastSync: new Date().toISOString() } : t
    ));
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="mb-2">Transmitters</h1>
        <p className="text-muted-foreground">Manage event transmitter configurations</p>
      </div>

      <div className="grid gap-4">
        {transmitters.map((transmitter) => (
          <Card key={transmitter.id}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-base">{transmitter.issuer}</CardTitle>
                <Button variant="outline" size="sm" onClick={() => syncTransmitter(transmitter.id)}>
                  <RefreshCw className="h-3 w-3 mr-2" />
                  Sync
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div>
                  <p className="text-sm text-muted-foreground mb-1">Supported Methods</p>
                  <div className="flex gap-2">
                    {transmitter.delivery_methods_supported.map((method) => (
                      <Badge key={method} variant="outline">
                        {method === 'urn:ietf:rfc:8935' ? 'Push' : 'Poll'}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground mb-1">Event Types</p>
                  <p className="text-sm">{transmitter.events_supported.length} supported</p>
                </div>
                {transmitter.lastSync && (
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Last Sync</p>
                    <p className="text-sm">{new Date(transmitter.lastSync).toLocaleString()}</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
