import fs from 'fs';
import path from 'path';

interface ScoreCategory {
  name: string;
  score: number;
  max: number;
  issues: string[];
  suggestions: string[];
}

export function analyzeProject() {
  console.log('🔍 Running secure-ref security analysis...\n');

  const categories: ScoreCategory[] = [
    { name: "Configuration", score: 0, max: 30, issues: [], suggestions: [] },
    { name: "Headers", score: 0, max: 25, issues: [], suggestions: [] },
    { name: "Environment", score: 0, max: 20, issues: [], suggestions: [] },
    { name: "Dependencies", score: 0, max: 15, issues: [], suggestions: [] },
    { name: "Runtime Protection", score: 0, max: 10, issues: [], suggestions: [] }
  ];

  let totalScore = 0;

  // 1. Configuration Check
  const configPath = path.join(process.cwd(), 'security.config.ts');
  if (fs.existsSync(configPath)) {
    categories[0].score = 30;
    categories[0].issues.push('✅ Using Smart Modes via security.config.ts');
  } else {
    categories[0].issues.push('❌ No security.config.ts found');
    categories[0].suggestions.push('Run: npx secure-ref init');
    categories[0].score = 10;
  }

  // 2. Environment Check
  const env = process.env.NODE_ENV || 'development';
  if (env === 'production') {
    categories[2].score = 20;
    categories[2].issues.push('✅ NODE_ENV=production');
  } else {
    categories[2].issues.push(`⚠️ NODE_ENV=${env} (should be production in live apps)`);
    categories[2].suggestions.push('Set NODE_ENV=production in production');
    categories[2].score = 8;
  }

  // 3. .env security
  const envPath = path.join(process.cwd(), '.env');
  if (fs.existsSync(envPath)) {
    const gitignorePath = path.join(process.cwd(), '.gitignore');
    if (fs.existsSync(gitignorePath)) {
      const gitignore = fs.readFileSync(gitignorePath, 'utf8');
      if (gitignore.includes('.env')) {
        categories[2].score += 5;
        categories[2].issues.push('✅ .env is gitignored');
      } else {
        categories[2].issues.push('❌ .env exists but not in .gitignore');
        categories[2].suggestions.push('Add .env to .gitignore');
      }
    }
  }

  // 4. Package check
  const pkgPath = path.join(process.cwd(), 'package.json');
  if (fs.existsSync(pkgPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    const version = pkg.dependencies?.['secure-ref'] || pkg.devDependencies?.['secure-ref'];
    if (version) {
      categories[3].score = 15;
      categories[3].issues.push(`✅ secure-ref v${version} installed`);
    } else {
      categories[3].issues.push('❌ secure-ref not found in dependencies');
      categories[3].suggestions.push('npm install secure-ref');
      categories[3].score = 5;
    }
  }

  // 5. Calculate total
  totalScore = categories.reduce((sum, cat) => sum + cat.score, 0);
  const maxScore = categories.reduce((sum, cat) => sum + cat.max, 0);
  const percentage = Math.round((totalScore / maxScore) * 100);

  const grade = 
    percentage >= 90 ? 'A+' : 
    percentage >= 80 ? 'A' : 
    percentage >= 70 ? 'B' : 
    percentage >= 50 ? 'C' : 'Risk';

  // Output Report
  console.log('📊 SecureRef Security Score Report');
  console.log('==================================\n');

  categories.forEach(cat => {
    const percent = Math.round((cat.score / cat.max) * 100);
    console.log(`${cat.name.padEnd(20)} ${cat.score}/${cat.max} (${percent}%)`);
    cat.issues.forEach(issue => console.log(`   ${issue}`));
    if (cat.suggestions.length > 0) {
      console.log(`   💡 Suggestions:`);
      cat.suggestions.forEach(s => console.log(`      • ${s}`));
    }
    console.log('');
  });

  console.log(`🎯 Overall Security Score: ${percentage}/100 → ${grade}`);
  
  if (percentage >= 90) {
    console.log('🏆 Excellent! Your project follows strong security practices.');
  } else if (percentage >= 70) {
    console.log('👍 Good, but there is room for improvement.');
  } else {
    console.log('🚨 Attention needed. Run "npx secure-ref init" and follow suggestions.');
  }

  console.log('\nAnalysis by secure-ref v1.3.0');
}
