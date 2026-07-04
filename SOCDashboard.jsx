import React from 'react';

const detectionData = [
  {
    id: 1,
    technique: 'Credential Access - LSASS Memory Dump',
    mitreId: 'T1003.001',
    process: 'mimikatz.exe accessed lsass.exe with rights 0x1010',
    whySuspicious: 'LSASS (Local Security Authority Subsystem Service) stores credentials in memory. Accessing it with PROCESS_VM_READ rights is a common credential theft technique.',
    detectionRule: 'Sysmon Event ID 10, target process = lsass.exe'
  },
  {
    id: 2,
    technique: 'Persistence - Hidden Registry Run Key',
    mitreId: 'T1547.001',
    process: 'a.exe wrote to HKLM\\...\\CurrentVersion\\Run pointing to taskhost.exe',
    whySuspicious: 'Registry Run Keys are a common persistence mechanism that executes programs on system startup. Hidden or unexpected entries are suspicious.',
    detectionRule: 'Sysmon Event ID 13, target path contains \\Run\\'
  },
  {
    id: 3,
    technique: 'Privilege Escalation - UAC Bypass via DelegateExecute',
    mitreId: 'T1548.002',
    process: 'explorer.exe modified ms-settings\\shell\\open\\command\\DelegateExecute, set default to cmd.exe',
    whySuspicious: 'Modifying DelegateExecute registry keys can bypass User Account Control (UAC) to elevate privileges without user consent.',
    detectionRule: 'Sysmon Event ID 13, target path contains DelegateExecute'
  }
];

const SOCDashboard = () => {
  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <h1 style={styles.title}>SOC Detection Results</h1>
        <p style={styles.subtitle}>Windows Attack Techniques Analysis</p>
      </header>
      <div style={styles.cardsContainer}>
        {detectionData.map((item) => (
          <div key={item.id} style={styles.card}>
            <div style={styles.cardHeader}>
              <h2 style={styles.techniqueName}>{item.technique}</h2>
              <span style={styles.mitreId}>{item.mitreId}</span>
            </div>
            <div style={styles.cardBody}>
              <div style={styles.detailSection}>
                <h3 style={styles.detailLabel}>Malicious Process</h3>
                <p style={styles.detailValue}>{item.process}</p>
              </div>
              <div style={styles.detailSection}>
                <h3 style={styles.detailLabel}>Why Suspicious</h3>
                <p style={styles.detailValue}>{item.whySuspicious}</p>
              </div>
              <div style={styles.detailSection}>
                <h3 style={styles.detailLabel}>Detection Rule</h3>
                <p style={styles.detailValue}>{item.detectionRule}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const styles = {
  container: {
    minHeight: '100vh',
    backgroundColor: '#0f1419',
    color: '#e6e6e6',
    fontFamily: 'system-ui, -apple-system, sans-serif',
    padding: '2rem',
    maxWidth: '1400px',
    margin: '0 auto'
  },
  header: {
    marginBottom: '3rem',
    textAlign: 'center'
  },
  title: {
    fontSize: '2.5rem',
    fontWeight: '700',
    marginBottom: '0.5rem',
    color: '#00ff88'
  },
  subtitle: {
    fontSize: '1.1rem',
    color: '#8b949e',
    margin: 0
  },
  cardsContainer: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))',
    gap: '2rem'
  },
  card: {
    backgroundColor: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '12px',
    padding: '1.5rem',
    boxShadow: '0 4px 6px rgba(0, 0, 0, 0.3)'
  },
  cardHeader: {
    marginBottom: '1.5rem',
    paddingBottom: '1rem',
    borderBottom: '1px solid #30363d'
  },
  techniqueName: {
    fontSize: '1.3rem',
    fontWeight: '600',
    margin: '0 0 0.5rem 0',
    color: '#ffffff'
  },
  mitreId: {
    display: 'inline-block',
    backgroundColor: '#21262d',
    color: '#00ff88',
    padding: '0.25rem 0.75rem',
    borderRadius: '6px',
    fontSize: '0.875rem',
    fontWeight: '600',
    fontFamily: "'Courier New', Courier, monospace"
  },
  cardBody: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem'
  },
  detailSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem'
  },
  detailLabel: {
    fontSize: '0.875rem',
    fontWeight: '600',
    color: '#8b949e',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    margin: 0
  },
  detailValue: {
    fontSize: '0.95rem',
    lineHeight: '1.6',
    color: '#e6e6e6',
    margin: 0,
    fontFamily: "'Courier New', Courier, monospace",
    backgroundColor: '#0f1419',
    padding: '0.75rem',
    borderRadius: '6px',
    border: '1px solid #30363d'
  }
};

export default SOCDashboard;
