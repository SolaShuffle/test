module.exports = {
  apps: [{
    name: 'website',
    script: 'index.js',
    watch: false,
    env: {
      NODE_ENV: 'production',
      PORT: 8822
    },
    error_file: 'logs/err.log',
    out_file: 'logs/out.log',
    time: true,
    instances: 1,
    exec_mode: 'fork',
    max_memory_restart: '1G',
    restart_delay: 3000,
    watch_delay: 1000,
    ignore_watch: ["node_modules", "logs", ".git"],
    max_restarts: 10
  }]
}; 