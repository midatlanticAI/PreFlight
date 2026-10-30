import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { PY_DESERIALIZE_001 } from '../lib/probes/v05/adapters/python/py-deserialize-001-unsafe-load.js';

const detect = (probe, content, path = 'app/views.py') => probe.detect([{ path, content }]);

describe('Python safe YAML loaders and unsafe deserialization regressions', () => {
  it.each(['SafeLoader', 'yaml.SafeLoader', 'CSafeLoader', 'yaml.CSafeLoader'])(
    'accepts explicit positional and keyword %s only for its own call',
    (loader) => {
      for (const code of [
        `yaml.load(data, ${loader})`,
        `yaml.load(data, Loader = ${loader})`,
        `yaml.load(stream=get_data(a, b), Loader=${loader})`,
        `yaml.load(\n    get_data(a, b), # input\n    Loader=${loader},\n)`,
      ]) {
        expect(detect(PY_DESERIALIZE_001, code)).toHaveLength(0);
      }
      expect(
        detect(PY_DESERIALIZE_001, `yaml.load(data); yaml.load(data, Loader=${loader})`)
      ).toHaveLength(1);
      expect(
        detect(PY_DESERIALIZE_001, `yaml.load(data, Loader=${loader}); yaml.load(data)`)
      ).toHaveLength(1);
    }
  );

  it('keeps upstream unsafe lines and clears every upstream safe-loader line', () => {
    const content = readFileSync('bench/recall/bandit/yaml_load.py', 'utf8');
    expect(detect(PY_DESERIALIZE_001, content).map((finding) => finding.line)).toEqual([9, 22]);
  });

  it.each([
    'yaml.load(data)',
    'yaml.load(data, Loader=yaml.Loader)',
    'yaml.load(data, yaml.UnsafeLoader)',
    'yaml.load(data, Loader=yaml.FullLoader)',
    'yaml.load(data, Loader=SafeLoaderCustom)',
    'yaml.load(data, Loader=yaml.SafeLoader.factory)',
    'yaml.load(data, Loader=SafeLoader())',
    'yaml.load(data, choose(SafeLoader))',
    'yaml.load(data, Loader=custom, note=SafeLoader)',
    'yaml.load(data, Loader="SafeLoader")',
    'yaml.load(data) # Loader=yaml.SafeLoader',
    'yaml.load("Loader=SafeLoader")',
    'yaml.load(data); yaml.safe_load(data)',
    'yaml.load(data, **options)',
    'yaml.load(data, SafeLoader, **options)',
    'yaml.load(\n data,\n Loader=yaml.UnsafeLoader\n)',
    'pickle.loads(body)',
    'pickle.load(body); yaml.load(data, SafeLoader)',
    'cPickle.loads(body)',
    'dill.load(body)',
    'joblib.load(body)',
    'pandas.read_pickle(body)',
    'pd.read_pickle(body)',
    'torch.load(path, weights_only=False)',
  ])('still flags unsafe or unresolved deserialization: %s', (code) => {
    expect(detect(PY_DESERIALIZE_001, code)).toHaveLength(1);
  });

  it.each([
    'yaml.safe_load(data)',
    'torch.load(path, weights_only=True)',
    'torch.load(path)',
    'json.loads(data)',
    '# yaml.load(data)',
    'message = "yaml.load(data)"',
    '"""\nyaml.load(data)\n"""',
    'yaml.load("a,b)#", Loader=yaml.SafeLoader)',
  ])('preserves safe APIs and ignores YAML call text: %s', (code) => {
    expect(detect(PY_DESERIALIZE_001, code)).toHaveLength(0);
  });

  it('reports the unsafe call start line after multiline safe calls', () => {
    expect(
      detect(PY_DESERIALIZE_001, 'yaml.load(\n data, Loader=SafeLoader\n)\nyaml.load(data)').map(
        (finding) => finding.line
      )
    ).toEqual([4]);
  });
});

it('retains Python test-file exclusions', () => {
  expect(detect(PY_DESERIALIZE_001, 'pickle.loads(body)', 'tests/test_db.py')).toEqual([]);
});
