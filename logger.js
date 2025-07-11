const { createLogger, format, transports } = require('winston');
const path = require('path');

const DailyRotateFile = require('winston-daily-rotate-file');

// Custom format for console logs
const consoleFormat = format.printf(({ level, message, timestamp, ...metadata }) => {
  const metaString = Object.keys(metadata).length ? JSON.stringify(metadata) : '';
  return `${timestamp} [${level.toUpperCase()}]: ${message} ${metaString}`;
});

const logger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.splat(),
    format.json(),
  ),
  transports: [
    // Console transport with pretty printing
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.timestamp(),
        consoleFormat
      )
    }),
    // Error log file
    new transports.File({ 
      filename: path.join(__dirname, 'logs', 'error.log'), 
      level: 'error' 
    }),
    // Combined log file
    new transports.File({ 
      filename: path.join(__dirname, 'logs', 'combined.log') 
    }),
    // Daily rotating file
    new DailyRotateFile({
      filename: path.join(__dirname, 'logs', 'application-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d'
    })
  ],
});

module.exports = logger;