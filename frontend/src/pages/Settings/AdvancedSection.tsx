import React, { useState } from 'react';
import { apiClient as api } from '../../api/client';

export interface AdvancedSectionProps {
  initialTopology?: any;
  initialEconomicState?: any;
}

export const AdvancedSection: React.FC<AdvancedSectionProps> = ({
  initialTopology,
  initialEconomicState,
}) => {
  const [topology, setTopology] = useState<any>(initialTopology || null);
  const [economicState, setEconomicState] = useState<any>(initialEconomicState || null);
  const [loaded, setLoaded] = useState(Boolean(initialTopology));
  const [loading, setLoading] = useState(false);

  const handleToggle = async (e: React.SyntheticEvent<HTMLDetailsElement>) => {
    const isOpened = e.currentTarget.open;
    if (isOpened && !loaded && !loading) {
      try {
        setLoading(true);
        const [topRes, econRes] = await Promise.all([
          api.get('/topology').catch(() => ({ data: { topology: null } })),
          api.get('/wallet/economic-stats').catch(() => ({ data: { state: null } })),
        ]);
        setTopology(topRes.data.topology);
        setEconomicState(econRes.data.state);
        setLoaded(true);
      } finally {
        setLoading(false);
      }
    }
  };

  return (
    <details className="details-section" onToggle={handleToggle}>
      <summary className="details-summary">Advanced settings</summary>

      {loading ? (
        <p className="muted text-center">Loading advanced details...</p>
      ) : loaded ? (
        <div>
          {/* Key Storage Overview */}
          <div>
            <h3 className="section-title">Key storage</h3>
            <div className="two-column-list">
              <div className="two-column-item">
                <span className="label-col">Storage nodes</span>
                <span className="value-col">
                  {topology ? `${topology.totalNodes} nodes` : 'Unavailable'}
                </span>
              </div>
              <div className="two-column-item">
                <span className="label-col">Foundation group</span>
                <span className="value-col">
                  {topology?.domains?.foundation
                    ? `${topology.domains.foundation.count ?? topology.domains.foundation.nodes} nodes (requires ${topology.domains.foundation.threshold})`
                    : 'Unavailable'}
                </span>
              </div>
              <div className="two-column-item">
                <span className="label-col">Public group</span>
                <span className="value-col">
                  {topology?.domains?.public
                    ? `${topology.domains.public.count ?? topology.domains.public.nodes} nodes (requires ${topology.domains.public.threshold})`
                    : 'Unavailable'}
                </span>
              </div>
              <div className="two-column-item">
                <span className="label-col">Private group</span>
                <span className="value-col">
                  {topology?.domains?.private
                    ? `${topology.domains.private.count ?? topology.domains.private.nodes} nodes (requires ${topology.domains.private.threshold})`
                    : 'Unavailable'}
                </span>
              </div>
            </div>
          </div>

          {/* Network Security Overview */}
          <div>
            <h3 className="section-title">Network security</h3>
            <div className="two-column-list">
              <div className="two-column-item">
                <span className="label-col">Total value secured</span>
                <span className="value-col">
                  {economicState?.totalValueSecuredMstc ?? '100.00'} MSTC
                </span>
              </div>
              <div className="two-column-item">
                <span className="label-col">Network stake</span>
                <span className="value-col">
                  {economicState?.totalEffectiveStake ?? '300,000'} SST
                </span>
              </div>
              <div className="two-column-item">
                <span className="label-col">Insurance reserve</span>
                <span className="value-col">
                  {economicState?.insuranceTreasuryBalanceMstc ?? '10.00'} MSTC
                </span>
              </div>
              <div className="two-column-item">
                <span className="label-col">Validator reward pool</span>
                <span className="value-col">
                  {economicState?.validatorRedistributionPoolMstc ?? '25.00'} MSTC
                </span>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </details>
  );
};

export default AdvancedSection;
