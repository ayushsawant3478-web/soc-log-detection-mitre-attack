import React from 'react';

const detectionData = [
  {
    id: 1,
    technique: 'Credential Access - LSASS Memory Dump',
    mitreId: 'T1003.001',
    process: 'mimikatz.exe accessed lsass.exe with rights 0x1010',
    whySuspicious: 'LSASS (Local Security Authority Subsystem Service) stores credentials in memory. Accessing it with PROCESS_VM_READ rights is a common credential theft technique.',
    detectionRule: 'Sysmon Event ID 10, target process = lsass.exe',
    category: {
      color: '#c23b22', // muted red-orange for Credential Access
      backgroundColor: '#fff0ed'
    }
  },
  {
    id: 2,
    technique: 'Persistence - Hidden Registry Run Key',
    mitreId: 'T1547.001',
    process: 'a.exe wrote to HKLM\\...\\CurrentVersion\\Run pointing to taskhost.exe',
    whySuspicious: 'Registry Run Keys are a common persistence mechanism that executes programs on system startup. Hidden or unexpected entries are suspicious.',
    detectionRule: 'Sysmon Event ID 13, target path contains \\Run\\',
    category: {
      color: '#9a6700', // muted amber for Persistence
      backgroundColor: '#fff7e6'
    }
  },
  {
    id: 3,
    technique: 'Privilege Escalation - UAC Bypass via DelegateExecute',
    mitreId: 'T1548.002',
    process: 'explorer.exe modified ms-settings\\shell\\open\\command\\DelegateExecute, set default to cmd.exe',
    whySuspicious: 'Modifying DelegateExecute registry keys can bypass User Account Control (UAC) to elevate privileges without user consent.',
    detectionRule: 'Sysmon Event ID 13, target path contains DelegateExecute',
    category: {
      color: '#6b21a8', // muted purple for Privilege Escalation
      backgroundColor: '#faf5ff'
    }
  }
];

const SOCDashboard = () => {
  return (
    <>
      <style>{`
        @keyframes fadeInUp {
          from {
            opacity: 0;
            transform: translateY(20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        .soc-card {
          animation: fadeInUp 0.6s ease-out forwards;
          opacity: 0;
          transform: translateY(20px);
          transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .soc-card:hover {
          transform: translateY(-4px);
          box-shadow: 0 12px 24px rgba(0, 0, 0, 0.1);
        }

        .detail-section {
          animation: fadeInUp 0.5s ease-out forwards;
          opacity: 0;
          transform: translateY(10px);
        }
      `}</style>
      <div style={styles.container}>
        <header style={styles.header}>
          <h1 style={styles.title}>SOC Detection Results</h1>
          <p style={styles.subtitle}>Windows Attack Techniques Analysis</p>
        </header>
        <div style={styles.cardsContainer}>
          {detectionData.map((item, index) => (
            <div 
              key={item.id} 
              className="soc-card" 
              style={{
                ...styles.card,
                animationDelay: `${index * 100}ms`
              }}
            >
              <div style={styles.cardHeader}>
                <h2 style={styles.techniqueName}>{item.technique}</h2>
                <span 
                  style={{
                    ...styles.mitreId,
                    backgroundColor: item.category.backgroundColor,
                    color: item.category.color
                  }}
                >
                  {item.mitreId}
                </span>
              </div>
              <div style={styles.cardBody}>
                <div 
                  className="detail-section" 
                  style={{
                    ...styles.detailSection,
                    animationDelay: `${index * 100 + 200}ms`
                  }}
                >
                  <h3 style={styles.detailLabel}>Malicious Process</h3>
                  <p style={styles.detailValue}>{item.process}</p>
                </div>
                <div 
                  className="detail-section" 
                  style={{
                    ...styles.detailSection,
                    animationDelay: `${index * 100 + 300}ms`
                  }}
                >
                  <h3 style={styles.detailLabel}>Why Suspicious</h3>
                  <p style={styles.detailValue}>{item.whySuspicious}</p>
                </div>
                <div 
                  className="detail-section" 
                  style={{
                    ...styles.detailSection,
                    animationDelay: `${index * 100 + 400}ms`
                  }}
                >
                  <h3 style={styles.detailLabel}>Detection Rule</h3>
                  <p style={styles.detailValue}>{item.detectionRule}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
};

const styles = {
  container: {
    minHeight: '100vh',
    backgroundColor: '#f8f9fa',
    color: '#1a1a1a',
    fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
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
    color: '#1a1a1a'
  },
  subtitle: {
    fontSize: '1.1rem',
    color: '#6b7280',
    margin: 0
  },
  cardsContainer: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))',
    gap: '2rem'
  },
  card: {
    backgroundColor: '#ffffff',
    border: '1px solid #e0e0e0',
    borderRadius: '12px',
    padding: '1.5rem',
    boxShadow: '0 4px 6px rgba(0, 0, 0, 0.05)',
    cursor: 'default'
  },
  cardHeader: {
    marginBottom: '1.75rem',
    paddingBottom: '1rem',
    borderBottom: '1px solid #e0e0e0'
  },
  techniqueName: {
    fontSize: '1.3rem',
    fontWeight: '600',
    margin: '0 0 0.5rem 0',
    color: '#1a1a1a'
  },
  mitreId: {
    display: 'inline-block',
    padding: '0.25rem 0.75rem',
    borderRadius: '6px',
    fontSize: '0.875rem',
    fontWeight: '600',
    fontFamily: "'Courier New', Courier, monospace"
  },
  cardBody: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.75rem'
  },
  detailSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem'
  },
  detailLabel: {
    fontSize: '0.875rem',
    fontWeight: '600',
    color: '#6b7280',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    margin: 0
  },
  detailValue: {
    fontSize: '0.95rem',
    lineHeight: '1.6',
    color: '#1a1a1a',
    margin: 0,
    fontFamily: "'Courier New', Courier, monospace",
    backgroundColor: '#f1f3f5',
    padding: '0.75rem',
    borderRadius: '6px',
    border: '1px solid #e0e0e0'
  }
};

export default SOCDashboard;
