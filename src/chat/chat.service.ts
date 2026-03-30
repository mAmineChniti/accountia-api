import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

export interface AiResponse {
  response: string;
  choices: string[];
  link: { text: string; url: string } | null;
  type: 'text' | 'choices' | 'analysis';
}

@Injectable()
export class ChatService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ChatService.name);
  private readonly AI_BASE_URL = 'http://127.0.0.1:8001';
  private pythonProcess: ChildProcess;

  onModuleInit() {
    this.logger.log('Starting Python AI Service...');
    
    const scriptPath = path.join(process.cwd(), 'ai_brain.py');
    let pythonExecutable = 'python';

    // Try to find the virtual environment python depending on OS
    const venvWinPath = path.join(process.cwd(), '.venv', 'Scripts', 'python.exe');
    const venvMacUnixPath = path.join(process.cwd(), '.venv', 'bin', 'python');

    if (fs.existsSync(venvWinPath)) {
      pythonExecutable = venvWinPath;
    } else if (fs.existsSync(venvMacUnixPath)) {
      pythonExecutable = venvMacUnixPath;
    }
    
    this.pythonProcess = spawn(pythonExecutable, [scriptPath], {
      stdio: 'pipe',
      detached: false,
      env: {
        ...process.env, // inherit PATH and all other env vars
        GEMINI_API_KEY: process.env.GEMINI_API_KEY ?? '',
      },
    });

    this.pythonProcess.stdout?.on('data', (data) => {
      const out = data.toString().trim();
      if (out) this.logger.log(`[Python AI]: ${out}`);
    });

    this.pythonProcess.stderr?.on('data', (data) => {
      const err = data.toString().trim();
      if (err) this.logger.debug(`[Python AI]: ${err}`);
    });

    this.pythonProcess.on('close', (code) => {
      this.logger.warn(`Python AI Service exited with code ${code}`);
    });
  }

  onModuleDestroy() {
    if (this.pythonProcess) {
      this.logger.log('Stopping Python AI Service...');
      this.pythonProcess.kill();
    }
  }

  async getAiResponse(
    role: string,
    query: string,
    history: Array<{ role: string; content: string }> = [],
    systemContext?: any,
  ): Promise<AiResponse> {
    try {
      const response = await fetch(`${this.AI_BASE_URL}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role, query, history, context: systemContext }),
      });
      const data = await response.json() as AiResponse;
      return data;
    } catch (error: any) {
      this.logger.error(`AI Service error: ${error.message}`);
      return {
        response: "Désolé, je rencontre une petite difficulté technique. Réessayez dans un instant.",
        choices: [],
        link: null,
        type: 'text',
      };
    }
  }
}
