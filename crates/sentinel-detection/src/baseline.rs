pub struct StatisticalBaseline {
    pub samples: Vec<f64>,
}

impl StatisticalBaseline {
    pub fn new() -> Self {
        Self { samples: Vec::new() }
    }

    pub fn add_sample(&mut self, sample: f64) {
        self.samples.push(sample);
        if self.samples.len() > 100 {
            self.samples.remove(0);
        }
    }

    pub fn mean(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.samples.iter().sum();
        sum / (self.samples.len() as f64)
    }

    pub fn std_dev(&self) -> f64 {
        if self.samples.len() < 2 {
            return 1.0;
        }
        let mean = self.mean();
        let variance: f64 = self.samples.iter().map(|&x| (x - mean).powi(2)).sum::<f64>()
            / ((self.samples.len() - 1) as f64);
        variance.sqrt().max(0.001)
    }

    pub fn z_score(&self, value: f64) -> f64 {
        let mean = self.mean();
        let std = self.std_dev();
        (value - mean) / std
    }
}

impl Default for StatisticalBaseline {
    fn default() -> Self {
        Self::new()
    }
}
